package server

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"hash"
	"io"
	"log"
	"math"
	rand2 "math/rand"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awcullen/opcua"
	"github.com/djherbis/buffer"
)

const (
	// sequenceHeaderSize is the size of the sequence header
	sequenceHeaderSize int = 8
)

var (
	channelIDLock = sync.Mutex{}
	channelID     = rand2.Uint32()
)

// serverSecureChannel implements a secure channel for binary data over Tcp.
type serverSecureChannel struct {
	sync.RWMutex
	srv                         *Server
	remoteCertificate           []byte
	remotePublicKey             *rsa.PublicKey
	remoteApplicationURI        string
	localNonce                  []byte
	remoteNonce                 []byte
	channelID                   uint32
	tokenIDLock                 sync.RWMutex
	tokenID                     uint32
	tokenLock                   sync.RWMutex
	securityPolicyURI           string
	securityMode                opcua.MessageSecurityMode
	remoteCertificateThumbprint []byte
	localEndpoint               opcua.EndpointDescription
	discoveryOnly               bool
	wg                          sync.WaitGroup
	sendingSemaphore            sync.Mutex
	receivingSemaphore          sync.Mutex
	responseCh                  chan struct {
		opcua.ServiceResponse
		uint32
	}
	sequenceNumberLock         sync.Mutex
	sequenceNumber             uint32
	sendingTokenID             uint32
	receivingTokenID           uint32
	localSigningKey            []byte
	localEncryptingKey         []byte
	localInitializationVector  []byte
	remoteSigningKey           []byte
	remoteEncryptingKey        []byte
	remoteInitializationVector []byte
	encryptionBuffer           []byte
	sendBuffer                 []byte
	receiveBuffer              []byte

	asymLocalKeySize              int
	asymRemoteKeySize             int
	asymLocalPlainTextBlockSize   int
	asymLocalCipherTextBlockSize  int
	asymLocalSignatureSize        int
	asymRemotePlainTextBlockSize  int
	asymRemoteCipherTextBlockSize int
	asymRemoteSignatureSize       int
	symEncryptionBlockSize        int
	symEncryptionKeySize          int
	symSignatureSize              int
	symSignatureKeySize           int

	asymSign       func(priv *rsa.PrivateKey, plainText []byte) ([]byte, error)
	asymVerify     func(pub *rsa.PublicKey, plainText, signature []byte) error
	asymEncrypt    func(pub *rsa.PublicKey, plainText []byte) ([]byte, error)
	asymDecrypt    func(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error)
	symHMACFactory func(key []byte) hash.Hash
	symSignHMAC    hash.Hash
	symVerifyHMAC  hash.Hash
	symSign        func(mac hash.Hash, plainText []byte) ([]byte, error)
	symVerify      func(mac hash.Hash, plainText, signature []byte) error

	symEncryptingBlockCipher cipher.Block
	symDecryptingBlockCipher cipher.Block
	trace                    bool

	receiveBufferSize uint32
	sendBufferSize    uint32
	maxMessageSize    uint32
	maxChunkCount     uint32
	endpointURL       string
	conn              net.Conn
	closed            bool
}

// newServerSecureChannel initializes a new instance of the UaTcpSecureChannel.
func newServerSecureChannel(srv *Server, conn net.Conn, receiveBufferSize, sendBufferSize, maxMessageSize, maxChunkCount uint32, trace bool) *serverSecureChannel {
	ch := &serverSecureChannel{
		srv:               srv,
		conn:              conn,
		receiveBufferSize: receiveBufferSize,
		sendBufferSize:    sendBufferSize,
		maxMessageSize:    maxMessageSize,
		maxChunkCount:     maxChunkCount,
		trace:             trace,
		channelID:         getNextServerChannelID(),
	}
	return ch
}

// LocalDescription gets the application description for the local application.
func (ch *serverSecureChannel) LocalDescription() opcua.ApplicationDescription {
	return ch.srv.LocalDescription()
}

// LocalCertificate gets the certificate for the local application.
func (ch *serverSecureChannel) LocalCertificate() []byte {
	return ch.srv.LocalCertificate()
}

// LocalPrivateKey gets the local private key.
func (ch *serverSecureChannel) LocalPrivateKey() *rsa.PrivateKey {
	return ch.srv.LocalPrivateKey()
}

// LocalEndpoint gets the endpoint for the local application.
func (ch *serverSecureChannel) LocalEndpoint() opcua.EndpointDescription {
	ch.RLock()
	defer ch.RUnlock()
	return ch.localEndpoint
}

// RemoteCertificate gets the certificate for the remote application.
func (ch *serverSecureChannel) RemoteCertificate() []byte {
	ch.RLock()
	defer ch.RUnlock()
	return ch.remoteCertificate
}

// RemotePublicKey gets the remote public key.
func (ch *serverSecureChannel) RemotePublicKey() *rsa.PublicKey {
	ch.RLock()
	defer ch.RUnlock()
	return ch.remotePublicKey
}

// ChannelID gets the channel id.
func (ch *serverSecureChannel) ChannelID() uint32 {
	ch.RLock()
	defer ch.RUnlock()
	return ch.channelID
}

// NamespaceURIs gets the namespace uris.
func (ch *serverSecureChannel) NamespaceURIs() []string {
	return ch.srv.NamespaceUris()
}

// ServerURIs gets the server uris.
func (ch *serverSecureChannel) ServerURIs() []string {
	return ch.srv.ServerUris()
}

// SecurityPolicyURI returns the SecurityPolicyURI.
func (ch *serverSecureChannel) SecurityPolicyURI() string {
	ch.RLock()
	defer ch.RUnlock()
	return ch.securityPolicyURI
}

// SecurityMode returns the SecurityMode.
func (ch *serverSecureChannel) SecurityMode() opcua.MessageSecurityMode {
	ch.RLock()
	defer ch.RUnlock()
	return ch.securityMode
}

// LocalReceiveBufferSize gets the size of the local receive buffer.
func (ch *serverSecureChannel) LocalReceiveBufferSize() uint32 {
	ch.RLock()
	defer ch.RUnlock()
	return ch.receiveBufferSize
}

// LocalSendBufferSize gets the size of the local send buffer.
func (ch *serverSecureChannel) LocalSendBufferSize() uint32 {
	ch.RLock()
	defer ch.RUnlock()
	return ch.sendBufferSize
}

// LocalMaxMessageSize gets the maximum size of message that may be received by the local endpoint.
func (ch *serverSecureChannel) LocalMaxMessageSize() uint32 {
	ch.RLock()
	defer ch.RUnlock()
	return ch.maxMessageSize
}

// LocalMaxChunkCount gets the maximum number of chunks that may be received by the local endpoint.
func (ch *serverSecureChannel) LocalMaxChunkCount() uint32 {
	ch.RLock()
	defer ch.RUnlock()
	return ch.maxChunkCount
}

// Open the secure channel to the remote endpoint.
func (ch *serverSecureChannel) Open() error {
	ch.Lock()
	defer ch.Unlock()
	if err := ch.onOpening(); err != nil {
		return err
	}
	if err := ch.onOpen(); err != nil {
		return err
	}
	err := ch.onOpened()
	return err
}

// Close the secure channel.
func (ch *serverSecureChannel) Close() error {
	ch.Lock()
	defer ch.Unlock()
	if err := ch.onClosing(); err != nil {
		return err
	}
	if err := ch.onClose(); err != nil {
		return err
	}
	err := ch.onClosed()
	return err
}

// Abort the secure channel.
func (ch *serverSecureChannel) Abort(reason opcua.StatusCode, message string) error {
	ch.Lock()
	defer ch.Unlock()
	if err := ch.onClosing(); err != nil {
		return err
	}
	if err := ch.onAbort(reason, message); err != nil {
		return err
	}
	err := ch.onClosed()
	return err
}

// Write the service response.
func (ch *serverSecureChannel) Write(res opcua.ServiceResponse, id uint32) error {
	if ch.trace {
		b, _ := json.MarshalIndent(res, "", " ")
		log.Printf("%s%s", reflect.TypeOf(res).Elem().Name(), b)
	}
	switch res1 := res.(type) {
	case *opcua.OpenSecureChannelResponse:
		err := ch.sendOpenSecureChannelResponse(res1, id)
		if err != nil {
			log.Printf("Error sending OpenSecureChannelResponse. %s\n", err)
		}
		return err
	default:
		err := ch.sendServiceResponse(res1, id)
		if err != nil {
			log.Printf("Error sending service response. %s\n", err)
		}
		return err
	}
}

func (ch *serverSecureChannel) onOpening() error {
	// log.Printf("onOpening secure channel.\n")
	return nil
}

func (ch *serverSecureChannel) onOpen() error {
	// log.Printf("onOpen secure channel.\n")
	buf := *(bytesPool.Get().(*[]byte))
	defer bytesPool.Put(&buf)
	_, err := ch.read(buf)
	if err != nil {
		// log.Printf("Error opening Transport Channel: %s \n", err.Error())
		return opcua.BadDecodingError
	}

	var reader = bytes.NewReader(buf)
	var ec = opcua.NewEncodingContext()
	var dec = opcua.NewBinaryDecoder(reader, ec)

	var msgType uint32
	if err := dec.ReadUInt32(&msgType); err != nil {
		return opcua.BadDecodingError
	}
	var msgLen uint32
	if err := dec.ReadUInt32(&msgLen); err != nil {
		return opcua.BadDecodingError
	}

	var remoteProtocolVersion, remoteReceiveBufferSize, remoteSendBufferSize, remoteMaxMessageSize, remoteMaxChunkCount uint32
	switch msgType {
	case opcua.MessageTypeHello:
		if msgLen < 28 {
			return opcua.BadDecodingError
		}
		if err != nil {
			return opcua.BadDecodingError
		}
		if err = dec.ReadUInt32(&remoteProtocolVersion); err != nil || remoteProtocolVersion < protocolVersion {
			return opcua.BadProtocolVersionUnsupported
		}
		if err = dec.ReadUInt32(&remoteReceiveBufferSize); err != nil {
			return opcua.BadDecodingError
		}
		if err = dec.ReadUInt32(&remoteSendBufferSize); err != nil {
			return opcua.BadDecodingError
		}
		if err = dec.ReadUInt32(&remoteMaxMessageSize); err != nil {
			return opcua.BadDecodingError
		}
		if err = dec.ReadUInt32(&remoteMaxChunkCount); err != nil {
			return opcua.BadDecodingError
		}
		if err := dec.ReadString(&ch.endpointURL); err != nil {
			return opcua.BadDecodingError
		}
		// log.Printf("-> Hello { ver: %d, rec: %d, snd: %d, msg: %d, chk: %d, ep: %s }\n", remoteProtocolVersion, ch.remoteReceiveBufferSize, ch.remoteSendBufferSize, ch.remoteMaxMessageSize, ch.remoteMaxChunkCount, ch.endpointUrl)

	default:
		return opcua.BadDecodingError
	}

	var writer = opcua.NewWriter(buf)
	var enc = opcua.NewBinaryEncoder(writer, ec)

	// limit the receive buffer to what the sender can send
	if ch.receiveBufferSize > remoteSendBufferSize {
		ch.receiveBufferSize = remoteSendBufferSize
	}
	// limit the send buffer to what the receiver can receive
	if ch.sendBufferSize > remoteReceiveBufferSize {
		ch.sendBufferSize = remoteReceiveBufferSize
	}
	// limit the max message size to what the receiver can receive
	if remoteMaxMessageSize > 0 && ch.maxMessageSize > remoteMaxMessageSize {
		ch.maxMessageSize = remoteMaxMessageSize
	}
	// limit the max chunk count to what the receiver can receive
	if remoteMaxChunkCount > 0 && ch.maxChunkCount > remoteMaxChunkCount {
		ch.maxChunkCount = remoteMaxChunkCount
	}
	enc.WriteUInt32(opcua.MessageTypeAck)
	enc.WriteUInt32(uint32(28))
	enc.WriteUInt32(protocolVersion)
	enc.WriteUInt32(ch.receiveBufferSize)
	enc.WriteUInt32(ch.sendBufferSize)
	enc.WriteUInt32(ch.maxMessageSize)
	enc.WriteUInt32(ch.maxChunkCount)
	_, err = ch.write(writer.Bytes())
	if err != nil {
		// log.Printf("Error opening Transport Channel: %s \n", err.Error())
		return opcua.BadEncodingError
	}
	// log.Printf("<- Ack { ver: %d, rec: %d, snd: %d, msg: %d, chk: %d, ep: %s }\n", serverProtocolVersion, ch.localReceiveBufferSize, ch.localSendBufferSize, ch.localMaxMessageSize, ch.localMaxChunkCount, ch.conn.RemoteAddr())

	ch.sendBuffer = make([]byte, ch.sendBufferSize)
	ch.receiveBuffer = make([]byte, ch.receiveBufferSize)
	ch.encryptionBuffer = make([]byte, ch.sendBufferSize)
	ch.tokenID = 0
	ch.sendingTokenID = 0
	ch.receivingTokenID = 0
	ch.responseCh = make(chan struct {
		opcua.ServiceResponse
		uint32
	}, 32)
	ch.setSecurityPolicy(opcua.SecurityPolicyURINone)

	// read first request, which must be an OpenSecureChannelRequest
	req, rid, err := ch.readRequest()
	if err != nil {
		log.Printf("Error receiving OpenSecureChannelRequest. %s\n", err)
		return err
	}
	oscr, ok := req.(*opcua.OpenSecureChannelRequest)
	if !ok {
		return opcua.BadDecodingError
	}
	ch.tokenLock.Lock()
	ch.tokenID = ch.getNextTokenID()
	ch.securityMode = oscr.SecurityMode
	if ch.securityMode != opcua.MessageSecurityModeNone {
		ch.localNonce = getNextNonce(int(ch.symEncryptionKeySize))
	} else {
		ch.localNonce = []byte{}
	}
	ch.remoteNonce = []byte(oscr.ClientNonce)
	ch.tokenLock.Unlock()
	for _, ep := range ch.srv.Endpoints() {
		if ep.TransportProfileURI == opcua.TransportProfileURIUaTcpTransport && ep.SecurityPolicyURI == ch.securityPolicyURI && ep.SecurityMode == ch.securityMode {
			ch.localEndpoint = ep
			break
		}
	}
	// connecting for discovery only
	if ch.localEndpoint.EndpointURL == "" && ch.securityPolicyURI == opcua.SecurityPolicyURINone && ch.securityMode == opcua.MessageSecurityModeNone {
		ch.discoveryOnly = true
		ch.localEndpoint = opcua.EndpointDescription{
			EndpointURL:       ch.srv.localDescription.DiscoveryURLs[0],
			Server:            ch.srv.localDescription,
			SecurityMode:      opcua.MessageSecurityModeNone,
			SecurityPolicyURI: opcua.SecurityPolicyURINone,
			UserIdentityTokens: []opcua.UserTokenPolicy{
				{
					PolicyID:          "Anonymous",
					TokenType:         opcua.UserTokenTypeAnonymous,
					SecurityPolicyURI: opcua.SecurityPolicyURINone,
				},
			},
			TransportProfileURI: opcua.TransportProfileURIUaTcpTransport,
			SecurityLevel:       0,
		}
	}

	if ch.securityMode != opcua.MessageSecurityModeNone {
		rc := ch.remoteCertificate
		if rc == nil {
			return opcua.BadSecurityChecksFailed
		}
		cert, err := x509.ParseCertificate(ch.remoteCertificate)
		if err != nil {
			return opcua.BadSecurityChecksFailed
		}
		valid, err := validateClientCertificate(cert, ch.srv.trustedCertsPath, ch.srv.suppressCertificateExpired, ch.srv.suppressCertificateChainIncomplete)
		if !valid {
			return err
		}
		if len(cert.URIs) > 0 {
			ch.remoteApplicationURI = cert.URIs[0].String()
		}
	}
	res := &opcua.OpenSecureChannelResponse{
		ResponseHeader: opcua.ResponseHeader{
			Timestamp:     time.Now(),
			RequestHandle: oscr.Header().RequestHandle,
		},
		ServerProtocolVersion: protocolVersion,
		SecurityToken: opcua.ChannelSecurityToken{
			ChannelID:       ch.channelID,
			TokenID:         ch.tokenID,
			CreatedAt:       time.Now(),
			RevisedLifetime: oscr.RequestedLifetime,
		},
		ServerNonce: opcua.ByteString(ch.localNonce),
	}
	ch.Write(res, rid)

	// log.Printf("Issued security token. %d , lifetime: %d\n", res.SecurityToken.TokenId, res.SecurityToken.RevisedLifetime)

	go ch.requestWorker()

	return nil
}

func (ch *serverSecureChannel) onOpened() error {
	// log.Printf("onOpened secure channel.\n")
	return nil
}

func (ch *serverSecureChannel) onClosing() error {
	// log.Printf("onClosing secure channel.\n")
	return nil
}

func (ch *serverSecureChannel) onClose() error {
	// log.Printf("onClose secure channel.\n")
	if ch.conn != nil {
		ch.conn.Close()
		ch.closed = true
		return nil
	}
	return nil
}

func (ch *serverSecureChannel) onClosed() error {
	// log.Printf("onClosed secure channel.\n")
	// ch.delete()
	return nil
}

func (ch *serverSecureChannel) onAbort(reason opcua.StatusCode, message string) error {
	// log.Printf("onAbort secure channel.\n")
	if ch.conn != nil {
		buf := *(bytesPool.Get().(*[]byte))
		defer bytesPool.Put(&buf)
		var writer = opcua.NewWriter(buf)
		var ec = opcua.NewEncodingContext()
		var enc = opcua.NewBinaryEncoder(writer, ec)
		enc.WriteUInt32(opcua.MessageTypeError)
		enc.WriteUInt32(uint32(16 + len(message)))
		enc.WriteUInt32(uint32(reason))
		enc.WriteString(message)
		_, err := ch.write(writer.Bytes())
		if err != nil {
			// log.Printf("Error aborting Transport Channel: %s \n", err.Error())
			return err
		}
		// log.Printf("<- Err { reason: 0x%X, message: %s }\n", uint32(reason), message)
		ch.conn.Close()
		ch.closed = true
		return nil
	}
	ch.closed = true
	return nil
}

// sendOpenSecureChannelResponse sends open secure channel service response on transport channel.
func (ch *serverSecureChannel) sendOpenSecureChannelResponse(res *opcua.OpenSecureChannelResponse, id uint32) error {
	ch.sendingSemaphore.Lock()
	defer ch.sendingSemaphore.Unlock()
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()
	var bodyEncoder = opcua.NewBinaryEncoder(bodyStream, ch)

	if err := bodyEncoder.WriteNodeID(opcua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary); err != nil {
		return opcua.BadEncodingError
	}

	if err := bodyEncoder.Encode(res); err != nil {
		return opcua.BadEncodingError
	}

	if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
		return opcua.BadEncodingLimitsExceeded
	}

	// write chunks
	var chunkCount int
	var bodyCount = int(bodyStream.Len())

	for bodyCount > 0 {
		chunkCount++
		if i := int(ch.maxChunkCount); i > 0 && chunkCount > i {
			return opcua.BadEncodingLimitsExceeded
		}

		// plan
		var plainHeaderSize int
		var paddingHeaderSize int
		var maxBodySize int
		var bodySize int
		var paddingSize int
		var chunkSize int
		if ch.securityMode != opcua.MessageSecurityModeNone {
			plainHeaderSize = 16 + len(ch.securityPolicyURI) + 28 + len(ch.LocalCertificate())
			if ch.asymRemoteCipherTextBlockSize > 256 {
				paddingHeaderSize = 2
			} else {
				paddingHeaderSize = 1
			}
			maxBodySize = (((int(ch.sendBufferSize) - plainHeaderSize) / ch.asymRemoteCipherTextBlockSize) * ch.asymRemotePlainTextBlockSize) - sequenceHeaderSize - paddingHeaderSize - ch.asymLocalSignatureSize
			if bodyCount < maxBodySize {
				bodySize = bodyCount
				paddingSize = (ch.asymRemotePlainTextBlockSize - ((sequenceHeaderSize + bodySize + paddingHeaderSize + ch.asymLocalSignatureSize) % ch.asymRemotePlainTextBlockSize)) % ch.asymRemotePlainTextBlockSize
			} else {
				bodySize = maxBodySize
				paddingSize = 0
			}
			chunkSize = plainHeaderSize + (((sequenceHeaderSize + bodySize + paddingSize + paddingHeaderSize + ch.asymLocalSignatureSize) / ch.asymRemotePlainTextBlockSize) * ch.asymRemoteCipherTextBlockSize)

		} else {
			plainHeaderSize = int(16 + len(ch.securityPolicyURI) + 8)
			paddingHeaderSize = 0
			paddingSize = 0
			maxBodySize = int(ch.sendBufferSize) - plainHeaderSize - sequenceHeaderSize - ch.asymLocalSignatureSize
			if bodyCount < maxBodySize {
				bodySize = bodyCount
			} else {
				bodySize = maxBodySize
			}
			chunkSize = plainHeaderSize + sequenceHeaderSize + bodySize + ch.asymLocalSignatureSize
		}

		var stream = opcua.NewWriter(ch.sendBuffer)
		var encoder = opcua.NewBinaryEncoder(stream, ch)

		// header
		encoder.WriteUInt32(opcua.MessageTypeOpenFinal)
		encoder.WriteUInt32(uint32(chunkSize))
		encoder.WriteUInt32(ch.channelID)

		// asymmetric security header
		encoder.WriteString(ch.securityPolicyURI)
		if ch.securityMode != opcua.MessageSecurityModeNone {
			encoder.WriteByteArray(ch.LocalCertificate())
			thumbprint := sha1.Sum(ch.remoteCertificate)
			encoder.WriteByteArray(thumbprint[:])
		} else {
			encoder.WriteByteArray(nil)
			encoder.WriteByteArray(nil)
		}

		if plainHeaderSize != stream.Len() {
			return opcua.BadEncodingError
		}

		// sequence header
		encoder.WriteUInt32(ch.getNextSequenceNumber())
		encoder.WriteUInt32(id)

		// body
		_, err := io.CopyN(stream, bodyStream, int64(bodySize))
		if err != nil {
			return err
		}
		bodyCount -= bodySize

		// padding
		if ch.securityMode != opcua.MessageSecurityModeNone {
			paddingByte := byte(paddingSize & 0xFF)
			encoder.WriteByte(paddingByte)
			for i := 0; i < paddingSize; i++ {
				encoder.WriteByte(paddingByte)
			}

			if paddingHeaderSize == 2 {
				extraPaddingByte := byte((paddingSize >> 8) & 0xFF)
				encoder.WriteByte(extraPaddingByte)
			}
		}

		if bodyCount > 0 {
			return opcua.BadEncodingError
		}

		// sign
		if ch.securityMode != opcua.MessageSecurityModeNone {
			signature, err := ch.asymSign(ch.LocalPrivateKey(), stream.Bytes())
			if err != nil {
				return err
			}
			if len(signature) != ch.asymLocalSignatureSize {
				return opcua.BadEncodingError
			}
			_, err = stream.Write(signature)
			if err != nil {
				return err
			}
		}

		// encrypt
		if ch.securityMode != opcua.MessageSecurityModeNone {
			plaintextLen := stream.Len()
			copy(ch.encryptionBuffer, stream.Bytes()[:plainHeaderSize])
			plainText := make([]byte, ch.asymRemotePlainTextBlockSize)
			jj := plainHeaderSize
			for ii := plainHeaderSize; ii < plaintextLen; ii += ch.asymRemotePlainTextBlockSize {
				copy(plainText, stream.Bytes()[ii:])
				// encrypt with remote public key.
				cipherText, err := ch.asymEncrypt(ch.remotePublicKey, plainText)
				if err != nil {
					return err
				}
				if len(cipherText) != ch.asymRemoteCipherTextBlockSize {
					return opcua.BadEncodingError
				}
				copy(ch.encryptionBuffer[jj:], cipherText)
				jj += ch.asymRemoteCipherTextBlockSize
			}
			if jj != chunkSize {
				return opcua.BadEncodingError
			}
			// pass buffer to transport
			_, err := ch.write(ch.encryptionBuffer[:chunkSize])
			if err != nil {
				return err
			}

		} else {

			if stream.Len() != chunkSize {
				return opcua.BadEncodingError
			}
			// pass buffer to transport
			_, err := ch.write(stream.Bytes())
			if err != nil {
				return err
			}
		}
	}

	// log.Printf("<- %s, %d, %s\n", reflect.TypeOf(res).Elem().Name(), res.Header().RequestHandle, res.Header().ServiceResult)
	return nil
}

// sendServiceResponse sends the service response on transport channel.
func (ch *serverSecureChannel) sendServiceResponse(response opcua.ServiceResponse, id uint32) error {
	ch.sendingSemaphore.Lock()
	defer ch.sendingSemaphore.Unlock()
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()
	var bodyEncoder = opcua.NewBinaryEncoder(bodyStream, ch)

	switch res := response.(type) {

	// frequent
	case *opcua.PublishResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDPublishResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.ReadResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDReadResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.BrowseResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDBrowseResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.BrowseNextResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDBrowseNextResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.TranslateBrowsePathsToNodeIDsResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDTranslateBrowsePathsToNodeIDsResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.WriteResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDWriteResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CallResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCallResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.HistoryReadResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDHistoryReadResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}

	// moderate
	case *opcua.GetEndpointsResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDGetEndpointsResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.OpenSecureChannelResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CloseSecureChannelResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCloseSecureChannelResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CreateSessionResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCreateSessionResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.ActivateSessionResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDActivateSessionResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CloseSessionResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCloseSessionResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CreateMonitoredItemsResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCreateMonitoredItemsResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.DeleteMonitoredItemsResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDDeleteMonitoredItemsResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CreateSubscriptionResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCreateSubscriptionResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.DeleteSubscriptionsResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDDeleteSubscriptionsResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.SetPublishingModeResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDSetPublishingModeResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.ServiceFault:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDServiceFaultEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}

		// rare
	case *opcua.ModifyMonitoredItemsResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDModifyMonitoredItemsResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.SetMonitoringModeResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDSetMonitoringModeResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.SetTriggeringResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDSetTriggeringResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.ModifySubscriptionResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDModifySubscriptionResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.RepublishResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDRepublishResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.TransferSubscriptionsResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDTransferSubscriptionsResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.FindServersResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDFindServersResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.FindServersOnNetworkResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDFindServersOnNetworkResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.RegisterServerResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDRegisterServerResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.RegisterServer2Response:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDRegisterServer2ResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.CancelResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDCancelResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.AddNodesResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDAddNodesResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.AddReferencesResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDAddReferencesResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.DeleteNodesResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDDeleteNodesResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.DeleteReferencesResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDDeleteReferencesResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.RegisterNodesResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDRegisterNodesResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.UnregisterNodesResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDUnregisterNodesResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.QueryFirstResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDQueryFirstResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.QueryNextResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDQueryNextResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	case *opcua.HistoryUpdateResponse:
		if err := bodyEncoder.WriteNodeID(opcua.ObjectIDHistoryUpdateResponseEncodingDefaultBinary); err != nil {
			return opcua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return opcua.BadEncodingError
		}
	default:
		return opcua.BadEncodingError
	}

	if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
		return opcua.BadEncodingLimitsExceeded
	}

	var chunkCount int
	var bodyCount = int(bodyStream.Len())

	for bodyCount > 0 {
		chunkCount++
		if i := int(ch.maxChunkCount); i > 0 && chunkCount > i {
			return opcua.BadEncodingLimitsExceeded
		}

		// plan
		var plainHeaderSize int
		var paddingHeaderSize int
		var maxBodySize int
		var bodySize int
		var paddingSize int
		var chunkSize int
		if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
			plainHeaderSize = 16
			if ch.symEncryptionBlockSize > 256 {
				paddingHeaderSize = 2
			} else {
				paddingHeaderSize = 1
			}
			maxBodySize = (((int(ch.sendBufferSize) - plainHeaderSize) / ch.symEncryptionBlockSize) * ch.symEncryptionBlockSize) - sequenceHeaderSize - paddingHeaderSize - ch.symSignatureSize
			if bodyCount < maxBodySize {
				bodySize = bodyCount
				paddingSize = (ch.symEncryptionBlockSize - ((sequenceHeaderSize + bodySize + paddingHeaderSize + ch.symSignatureSize) % ch.symEncryptionBlockSize)) % ch.symEncryptionBlockSize
			} else {
				bodySize = maxBodySize
				paddingSize = 0
			}
			chunkSize = plainHeaderSize + sequenceHeaderSize + bodySize + paddingSize + paddingHeaderSize + ch.symSignatureSize

		} else {
			plainHeaderSize = 16
			paddingHeaderSize = 0
			paddingSize = 0
			maxBodySize = int(ch.sendBufferSize) - plainHeaderSize - sequenceHeaderSize - ch.symSignatureSize
			if bodyCount < maxBodySize {
				bodySize = bodyCount
			} else {
				bodySize = maxBodySize
			}
			chunkSize = plainHeaderSize + sequenceHeaderSize + bodySize + ch.symSignatureSize
		}

		var stream = opcua.NewWriter(ch.sendBuffer)
		var encoder = opcua.NewBinaryEncoder(stream, ch)

		// header
		if bodyCount > bodySize {
			encoder.WriteUInt32(opcua.MessageTypeChunk)
		} else {
			encoder.WriteUInt32(opcua.MessageTypeFinal)
		}
		encoder.WriteUInt32(uint32(chunkSize))
		encoder.WriteUInt32(ch.channelID)

		// symmetric security header
		encoder.WriteUInt32(ch.sendingTokenID)

		if plainHeaderSize != stream.Len() {
			return opcua.BadEncodingError
		}

		// sequence header
		encoder.WriteUInt32(ch.getNextSequenceNumber())
		encoder.WriteUInt32(id)

		// body
		_, err := io.CopyN(stream, bodyStream, int64(bodySize))
		if err != nil {
			return err
		}
		bodyCount -= bodySize

		// padding
		if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
			paddingByte := byte(paddingSize & 0xFF)
			encoder.WriteByte(paddingByte)
			for i := 0; i < paddingSize; i++ {
				encoder.WriteByte(paddingByte)
			}

			if paddingHeaderSize == 2 {
				extraPaddingByte := byte((paddingSize >> 8) & 0xFF)
				encoder.WriteByte(extraPaddingByte)
			}
		}

		// sign
		if ch.securityMode != opcua.MessageSecurityModeNone {
			signature, err := ch.symSign(ch.symSignHMAC, stream.Bytes())
			if err != nil {
				return err
			}
			stream.Write(signature)
		}

		// encrypt
		if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
			symEncryptor := cipher.NewCBCEncrypter(ch.symEncryptingBlockCipher, ch.localInitializationVector)
			symEncryptor.CryptBlocks(stream.Bytes()[plainHeaderSize:], stream.Bytes()[plainHeaderSize:])
		}

		// pass buffer to transport
		_, err = ch.write(stream.Bytes())
		if err != nil {
			return err
		}
		//fmt.Printf("%t, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d \n", bodyCount == 0, ch.sequenceNumber, id, bodySize, chunkSize, plainHeaderSize, serverSequenceHeaderSize, paddingSize, paddingHeaderSize, ch.symSignatureSize, stream.Len(), written)
	}

	// log.Printf("<- %s, %d, %s\n", reflect.TypeOf(res).Elem().Name(), res.Header().RequestHandle, res.Header().ServiceResult)
	return nil
}

// readRequest receives next service request from transport channel.
func (ch *serverSecureChannel) readRequest() (opcua.ServiceRequest, uint32, error) {
	ch.receivingSemaphore.Lock()
	defer ch.receivingSemaphore.Unlock()
	var req opcua.ServiceRequest
	var id uint32
	var plainHeaderSize int
	var paddingHeaderSize int
	var bodySize int
	var paddingSize int
	var channelID uint32
	var tokenID uint32
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()
	var bodyDecoder = opcua.NewBinaryDecoder(bodyStream, ch)

	// read chunks
	var chunkCount int32
	var isFinal bool

	for !isFinal {
		chunkCount++
		if i := int32(ch.maxChunkCount); i > 0 && chunkCount > i {
			return nil, 0, opcua.BadEncodingLimitsExceeded
		}

		count, err := ch.read(ch.receiveBuffer)
		if err != nil || count == 0 {
			return nil, 0, opcua.BadSecureChannelClosed
		}

		var stream = bytes.NewReader(ch.receiveBuffer[0:count])
		var decoder = opcua.NewBinaryDecoder(stream, ch)

		var messageType uint32
		if err := decoder.ReadUInt32(&messageType); err != nil {
			return nil, 0, err
		}
		var messageLength uint32
		if err := decoder.ReadUInt32(&messageLength); err != nil {
			return nil, 0, err
		}

		if count != int(messageLength) {
			return nil, 0, opcua.BadDecodingError
		}

		switch messageType {
		case opcua.MessageTypeChunk, opcua.MessageTypeFinal, opcua.MessageTypeCloseFinal:

			// header
			if err := decoder.ReadUInt32(&channelID); err != nil {
				return nil, 0, opcua.BadDecodingError
			}
			if channelID != ch.channelID {
				return nil, 0, opcua.BadTCPSecureChannelUnknown
			}

			// symmetric security header
			if err = decoder.ReadUInt32(&tokenID); err != nil {
				return nil, 0, opcua.BadDecodingError
			}

			// detect new token
			ch.tokenLock.RLock()
			if ch.receivingTokenID != tokenID {
				ch.receivingTokenID = tokenID

				if ch.securityMode != opcua.MessageSecurityModeNone {
					// (re)create security keys for decrypting, verifying
					remoteSecurityKey := calculatePSHA(ch.localNonce, ch.remoteNonce, ch.symSignatureKeySize+ch.symEncryptionKeySize+ch.symEncryptionBlockSize, ch.securityPolicyURI)
					ch.remoteSigningKey = make([]byte, ch.symSignatureKeySize)
					ch.remoteEncryptingKey = make([]byte, ch.symEncryptionKeySize)
					ch.remoteInitializationVector = make([]byte, ch.symEncryptionBlockSize)
					copy(ch.remoteSigningKey[:ch.symSignatureKeySize], remoteSecurityKey)
					copy(ch.remoteEncryptingKey[:ch.symEncryptionKeySize], remoteSecurityKey[ch.symSignatureKeySize:])
					copy(ch.remoteInitializationVector[:ch.symEncryptionBlockSize], remoteSecurityKey[ch.symSignatureKeySize+ch.symEncryptionKeySize:])
					// update with new keys
					ch.symVerifyHMAC = ch.symHMACFactory(ch.remoteSigningKey)
					if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
						if cipher, err := aes.NewCipher(ch.remoteEncryptingKey); err == nil {
							ch.symDecryptingBlockCipher = cipher
						} else {
							ch.tokenLock.RUnlock()
							return nil, 0, opcua.BadDecodingError
						}
					}
				}

				ch.sendingTokenID = tokenID
				if ch.securityMode != opcua.MessageSecurityModeNone {

					// (re)create security keys for signing, encrypting
					localSecurityKey := calculatePSHA(ch.remoteNonce, ch.localNonce, ch.symSignatureKeySize+ch.symEncryptionKeySize+ch.symEncryptionBlockSize, ch.securityPolicyURI)
					ch.localSigningKey = make([]byte, ch.symSignatureKeySize)
					ch.localEncryptingKey = make([]byte, ch.symEncryptionKeySize)
					ch.localInitializationVector = make([]byte, ch.symEncryptionBlockSize)
					copy(ch.localSigningKey[:ch.symSignatureKeySize], localSecurityKey)
					copy(ch.localEncryptingKey[:ch.symEncryptionKeySize], localSecurityKey[ch.symSignatureKeySize:])
					copy(ch.localInitializationVector[:ch.symEncryptionBlockSize], localSecurityKey[ch.symSignatureKeySize+ch.symEncryptionKeySize:])

					// update signer and encrypter with new symmetric keys
					ch.symSignHMAC = ch.symHMACFactory(ch.localSigningKey)
					if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
						if cipher, err := aes.NewCipher(ch.localEncryptingKey); err == nil {
							ch.symEncryptingBlockCipher = cipher
						} else {
							ch.tokenLock.RUnlock()
							return nil, 0, opcua.BadDecodingError
						}
					}
				}

				// log.Printf("Installed security token. %d\n", ch.sendingTokenId)
			}
			ch.tokenLock.RUnlock()

			plainHeaderSize = 16
			// decrypt
			if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
				span := ch.receiveBuffer[plainHeaderSize:count]
				if len(span)%ch.symDecryptingBlockCipher.BlockSize() != 0 {
					return nil, 0, opcua.BadEncodingError
				}
				symDecryptor := cipher.NewCBCDecrypter(ch.symDecryptingBlockCipher, ch.remoteInitializationVector)
				symDecryptor.CryptBlocks(span, span)
			}

			// verify
			if ch.securityMode != opcua.MessageSecurityModeNone {
				sigEnd := int(messageLength)
				sigStart := sigEnd - ch.symSignatureSize
				err := ch.symVerify(ch.symVerifyHMAC, ch.receiveBuffer[:sigStart], ch.receiveBuffer[sigStart:sigEnd])
				if err != nil {
					return nil, 0, err
				}
			}

			// read sequence header
			var unused uint32
			if err = decoder.ReadUInt32(&unused); err != nil {
				return nil, 0, opcua.BadDecodingError
			}

			if err = decoder.ReadUInt32(&id); err != nil {
				return nil, 0, opcua.BadDecodingError
			}

			// body
			if ch.securityMode == opcua.MessageSecurityModeSignAndEncrypt {
				if ch.symEncryptionBlockSize > 256 {
					paddingHeaderSize = 2
					start := int(messageLength) - ch.symSignatureSize - paddingHeaderSize
					paddingSize = int(binary.LittleEndian.Uint16(ch.receiveBuffer[start : start+2]))
				} else {
					paddingHeaderSize = 1
					start := int(messageLength) - ch.symSignatureSize - paddingHeaderSize
					paddingSize = int(ch.receiveBuffer[start])
				}
				bodySize = int(messageLength) - plainHeaderSize - sequenceHeaderSize - paddingSize - paddingHeaderSize - ch.symSignatureSize

			} else {
				bodySize = int(messageLength) - plainHeaderSize - sequenceHeaderSize - ch.symSignatureSize
			}

			m := plainHeaderSize + sequenceHeaderSize
			n := m + bodySize
			if _, err := bodyStream.Write(ch.receiveBuffer[m:n]); err != nil {
				return nil, 0, err
			}
			isFinal = messageType != opcua.MessageTypeChunk

		case opcua.MessageTypeOpenFinal:
			// header
			if err = decoder.ReadUInt32(&channelID); err != nil {
				return nil, 0, opcua.BadDecodingError
			}
			// asymmetric header
			var securityPolicyURI string
			if err := decoder.ReadString(&securityPolicyURI); err != nil {
				return nil, 0, opcua.BadDecodingError
			}
			if err := decoder.ReadByteArray(&ch.remoteCertificate); err != nil {
				return nil, 0, opcua.BadDecodingError
			}
			if err := decoder.ReadByteArray(&ch.remoteCertificateThumbprint); err != nil {
				return nil, 0, opcua.BadDecodingError
			}
			plainHeaderSize = count - stream.Len()

			err = ch.setSecurityPolicy(securityPolicyURI)
			if err != nil {
				return nil, 0, opcua.BadDecodingError
			}

			// decrypt
			if ch.securityPolicyURI != opcua.SecurityPolicyURINone {

				cipherText := make([]byte, ch.asymLocalCipherTextBlockSize)
				jj := plainHeaderSize
				for ii := plainHeaderSize; ii < int(messageLength); ii += ch.asymLocalCipherTextBlockSize {
					copy(cipherText, ch.receiveBuffer[ii:])
					// decrypt with local private key.
					plainText, err := ch.asymDecrypt(ch.LocalPrivateKey(), cipherText)
					if err != nil {
						return nil, 0, err
					}
					if len(plainText) != ch.asymLocalPlainTextBlockSize {
						return nil, 0, opcua.BadEncodingError
					}
					copy(ch.receiveBuffer[jj:], plainText)
					jj += ch.asymLocalPlainTextBlockSize
				}

				messageLength = uint32(jj) // msg is shorter after decryption

			}

			// verify
			if ch.securityPolicyURI != opcua.SecurityPolicyURINone {
				// verify with remote public key.
				sigEnd := int(messageLength)
				sigStart := sigEnd - ch.asymRemoteSignatureSize
				err := ch.asymVerify(ch.remotePublicKey, ch.receiveBuffer[:sigStart], ch.receiveBuffer[sigStart:sigEnd])
				if err != nil {
					return nil, 0, opcua.BadDecodingError
				}
			}

			// sequence header
			var unused uint32
			if err := decoder.ReadUInt32(&unused); err != nil {
				return nil, 0, opcua.BadDecodingError
			}

			if err := decoder.ReadUInt32(&id); err != nil {
				return nil, 0, opcua.BadDecodingError
			}

			// body
			if ch.securityPolicyURI != opcua.SecurityPolicyURINone {
				if ch.asymLocalCipherTextBlockSize > 256 {
					paddingHeaderSize = 2
					start := int(messageLength) - ch.asymRemoteSignatureSize - paddingHeaderSize
					paddingSize = int(binary.LittleEndian.Uint16(ch.receiveBuffer[start : start+2]))
				} else {
					paddingHeaderSize = 1
					start := int(messageLength) - ch.asymRemoteSignatureSize - paddingHeaderSize
					paddingSize = int(ch.receiveBuffer[start])
				}
				bodySize = int(messageLength) - plainHeaderSize - sequenceHeaderSize - paddingSize - paddingHeaderSize - ch.asymRemoteSignatureSize

			} else {
				bodySize = int(messageLength) - plainHeaderSize - sequenceHeaderSize - ch.asymRemoteSignatureSize
			}

			m := plainHeaderSize + sequenceHeaderSize
			n := m + bodySize
			if _, err := bodyStream.Write(ch.receiveBuffer[m:n]); err != nil {
				return nil, 0, err
			}

			isFinal = messageType == opcua.MessageTypeOpenFinal

		case opcua.MessageTypeError, opcua.MessageTypeAbort:
			var statusCode uint32
			if err := decoder.ReadUInt32(&statusCode); err != nil {
				return nil, 0, opcua.BadDecodingError
			}
			var message string
			if err := decoder.ReadString(&message); err != nil {
				return nil, 0, opcua.BadDecodingError
			}
			log.Printf("Server sent error response. %s %s\n", opcua.StatusCode(statusCode).Error(), message)
			return nil, 0, opcua.StatusCode(statusCode)

		default:
			return nil, 0, opcua.BadUnknownResponse
		}

		if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
			return nil, 0, opcua.BadEncodingLimitsExceeded
		}
	}

	var nodeID opcua.NodeID
	if err := bodyDecoder.ReadNodeID(&nodeID); err != nil {
		return nil, 0, opcua.BadDecodingError
	}
	var temp interface{}
	switch nodeID {

	// frequent
	case opcua.ObjectIDPublishRequestEncodingDefaultBinary:
		temp = new(opcua.PublishRequest)
	case opcua.ObjectIDReadRequestEncodingDefaultBinary:
		temp = new(opcua.ReadRequest)
	case opcua.ObjectIDBrowseRequestEncodingDefaultBinary:
		temp = new(opcua.BrowseRequest)
	case opcua.ObjectIDBrowseNextRequestEncodingDefaultBinary:
		temp = new(opcua.BrowseNextRequest)
	case opcua.ObjectIDTranslateBrowsePathsToNodeIDsRequestEncodingDefaultBinary:
		temp = new(opcua.TranslateBrowsePathsToNodeIDsRequest)
	case opcua.ObjectIDWriteRequestEncodingDefaultBinary:
		temp = new(opcua.WriteRequest)
	case opcua.ObjectIDCallRequestEncodingDefaultBinary:
		temp = new(opcua.CallRequest)
	case opcua.ObjectIDHistoryReadRequestEncodingDefaultBinary:
		temp = new(opcua.HistoryReadRequest)

	// moderate
	case opcua.ObjectIDGetEndpointsRequestEncodingDefaultBinary:
		temp = new(opcua.GetEndpointsRequest)
	case opcua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary:
		temp = new(opcua.OpenSecureChannelRequest)
	case opcua.ObjectIDCloseSecureChannelRequestEncodingDefaultBinary:
		temp = new(opcua.CloseSecureChannelRequest)
	case opcua.ObjectIDCreateSessionRequestEncodingDefaultBinary:
		temp = new(opcua.CreateSessionRequest)
	case opcua.ObjectIDActivateSessionRequestEncodingDefaultBinary:
		temp = new(opcua.ActivateSessionRequest)
	case opcua.ObjectIDCloseSessionRequestEncodingDefaultBinary:
		temp = new(opcua.CloseSessionRequest)
	case opcua.ObjectIDCreateMonitoredItemsRequestEncodingDefaultBinary:
		temp = new(opcua.CreateMonitoredItemsRequest)
	case opcua.ObjectIDDeleteMonitoredItemsRequestEncodingDefaultBinary:
		temp = new(opcua.DeleteMonitoredItemsRequest)
	case opcua.ObjectIDCreateSubscriptionRequestEncodingDefaultBinary:
		temp = new(opcua.CreateSubscriptionRequest)
	case opcua.ObjectIDDeleteSubscriptionsRequestEncodingDefaultBinary:
		temp = new(opcua.DeleteSubscriptionsRequest)
	case opcua.ObjectIDSetPublishingModeRequestEncodingDefaultBinary:
		temp = new(opcua.SetPublishingModeRequest)

		// rare
	case opcua.ObjectIDModifyMonitoredItemsRequestEncodingDefaultBinary:
		temp = new(opcua.ModifyMonitoredItemsRequest)
	case opcua.ObjectIDSetMonitoringModeRequestEncodingDefaultBinary:
		temp = new(opcua.SetMonitoringModeRequest)
	case opcua.ObjectIDSetTriggeringRequestEncodingDefaultBinary:
		temp = new(opcua.SetTriggeringRequest)
	case opcua.ObjectIDModifySubscriptionRequestEncodingDefaultBinary:
		temp = new(opcua.ModifySubscriptionRequest)
	case opcua.ObjectIDRepublishRequestEncodingDefaultBinary:
		temp = new(opcua.RepublishRequest)
	case opcua.ObjectIDTransferSubscriptionsRequestEncodingDefaultBinary:
		temp = new(opcua.TransferSubscriptionsRequest)
	case opcua.ObjectIDFindServersRequestEncodingDefaultBinary:
		temp = new(opcua.FindServersRequest)
	case opcua.ObjectIDFindServersOnNetworkRequestEncodingDefaultBinary:
		temp = new(opcua.FindServersOnNetworkRequest)
	case opcua.ObjectIDRegisterServerRequestEncodingDefaultBinary:
		temp = new(opcua.RegisterServerRequest)
	case opcua.ObjectIDRegisterServer2RequestEncodingDefaultBinary:
		temp = new(opcua.RegisterServer2Request)
	case opcua.ObjectIDCancelRequestEncodingDefaultBinary:
		temp = new(opcua.CancelRequest)
	case opcua.ObjectIDAddNodesRequestEncodingDefaultBinary:
		temp = new(opcua.AddNodesRequest)
	case opcua.ObjectIDAddReferencesRequestEncodingDefaultBinary:
		temp = new(opcua.AddReferencesRequest)
	case opcua.ObjectIDDeleteNodesRequestEncodingDefaultBinary:
		temp = new(opcua.DeleteNodesRequest)
	case opcua.ObjectIDDeleteReferencesRequestEncodingDefaultBinary:
		temp = new(opcua.DeleteReferencesRequest)
	case opcua.ObjectIDRegisterNodesRequestEncodingDefaultBinary:
		temp = new(opcua.RegisterNodesRequest)
	case opcua.ObjectIDUnregisterNodesRequestEncodingDefaultBinary:
		temp = new(opcua.UnregisterNodesRequest)
	case opcua.ObjectIDQueryFirstRequestEncodingDefaultBinary:
		temp = new(opcua.QueryFirstRequest)
	case opcua.ObjectIDQueryNextRequestEncodingDefaultBinary:
		temp = new(opcua.QueryNextRequest)
	case opcua.ObjectIDHistoryUpdateRequestEncodingDefaultBinary:
		temp = new(opcua.HistoryUpdateRequest)
	default:
		return nil, 0, opcua.BadDecodingError
	}

	// decode fields from message stream
	if err := bodyDecoder.Decode(temp); err != nil {
		return nil, 0, opcua.BadDecodingError
	}
	req = temp.(opcua.ServiceRequest)

	if ch.trace {
		b, _ := json.MarshalIndent(req, "", " ")
		log.Printf("%s%s", reflect.TypeOf(req).Elem().Name(), b)
	}

	return req, id, nil
}

// requestWorker starts a task to receive service requests from transport channel.
func (ch *serverSecureChannel) requestWorker() {
	ch.wg.Add(1)
	for {
		req, id, err := ch.readRequest()
		if err != nil {
			if err != opcua.BadSecureChannelClosed {
				log.Printf("Error receiving request. %s\n", err)
			}
			ch.wg.Done()
			return
		}
		err = ch.handleRequest(req, id)
		if err != nil {
			log.Printf("Error handling request. %s\n", err)
		}
	}
}

// handleRequest directs the request to the correct handler depending on the type of request.
func (ch *serverSecureChannel) handleRequest(req opcua.ServiceRequest, requestid uint32) error {
	switch req := req.(type) {
	case *opcua.PublishRequest:
		return ch.srv.handlePublish(ch, requestid, req)
	case *opcua.RepublishRequest:
		return ch.srv.handleRepublish(ch, requestid, req)
	case *opcua.ReadRequest:
		return ch.srv.handleRead(ch, requestid, req)
	case *opcua.WriteRequest:
		return ch.srv.handleWrite(ch, requestid, req)
	case *opcua.CallRequest:
		return ch.srv.handleCall(ch, requestid, req)
	case *opcua.BrowseRequest:
		return ch.srv.handleBrowse(ch, requestid, req)
	case *opcua.BrowseNextRequest:
		return ch.srv.handleBrowseNext(ch, requestid, req)
	case *opcua.TranslateBrowsePathsToNodeIDsRequest:
		return ch.srv.handleTranslateBrowsePathsToNodeIds(ch, requestid, req)
	case *opcua.CreateSubscriptionRequest:
		return ch.srv.handleCreateSubscription(ch, requestid, req)
	case *opcua.ModifySubscriptionRequest:
		return ch.srv.handleModifySubscription(ch, requestid, req)
	case *opcua.SetPublishingModeRequest:
		return ch.srv.handleSetPublishingMode(ch, requestid, req)
	case *opcua.DeleteSubscriptionsRequest:
		return ch.srv.handleDeleteSubscriptions(ch, requestid, req)
	case *opcua.CreateMonitoredItemsRequest:
		return ch.srv.handleCreateMonitoredItems(ch, requestid, req)
	case *opcua.ModifyMonitoredItemsRequest:
		return ch.srv.handleModifyMonitoredItems(ch, requestid, req)
	case *opcua.SetMonitoringModeRequest:
		return ch.srv.handleSetMonitoringMode(ch, requestid, req)
	case *opcua.DeleteMonitoredItemsRequest:
		return ch.srv.handleDeleteMonitoredItems(ch, requestid, req)
	case *opcua.HistoryReadRequest:
		return ch.srv.handleHistoryRead(ch, requestid, req)
	case *opcua.CreateSessionRequest:
		return ch.srv.handleCreateSession(ch, requestid, req)
	case *opcua.ActivateSessionRequest:
		return ch.srv.handleActivateSession(ch, requestid, req)
	case *opcua.CloseSessionRequest:
		return ch.srv.handleCloseSession(ch, requestid, req)
	case *opcua.OpenSecureChannelRequest:
		return ch.handleOpenSecureChannel(requestid, req)
	case *opcua.CloseSecureChannelRequest:
		return ch.srv.handleCloseSecureChannel(ch, requestid, req)
	case *opcua.FindServersRequest:
		return ch.srv.findServers(ch, requestid, req)
	case *opcua.GetEndpointsRequest:
		return ch.srv.getEndpoints(ch, requestid, req)
	case *opcua.RegisterNodesRequest:
		return ch.srv.handleRegisterNodes(ch, requestid, req)
	case *opcua.UnregisterNodesRequest:
		return ch.srv.handleUnregisterNodes(ch, requestid, req)
	case *opcua.SetTriggeringRequest:
		return ch.srv.handleSetTriggering(ch, requestid, req)
	case *opcua.CancelRequest:
		return ch.srv.handleCancel(ch, requestid, req)

	default:
		ch.Write(
			&opcua.ServiceFault{
				ResponseHeader: opcua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.Header().RequestHandle,
					ServiceResult: opcua.BadServiceUnsupported,
				},
			},
			requestid,
		)
		return nil
	}
}

func (ch *serverSecureChannel) handleOpenSecureChannel(requestid uint32, req *opcua.OpenSecureChannelRequest) error {
	if req.RequestType == opcua.SecurityTokenRequestTypeIssue {
		return opcua.BadSecurityChecksFailed
	}
	// handle renew token
	ch.tokenLock.Lock()
	ch.tokenID = ch.getNextTokenID()
	if ch.securityMode != opcua.MessageSecurityModeNone {
		ch.localNonce = getNextNonce(int(ch.symEncryptionKeySize))
	} else {
		ch.localNonce = []byte{}
	}
	ch.remoteNonce = []byte(req.ClientNonce)
	ch.tokenLock.Unlock()
	res := &opcua.OpenSecureChannelResponse{
		ResponseHeader: opcua.ResponseHeader{
			Timestamp:     time.Now(),
			RequestHandle: req.Header().RequestHandle,
		},
		ServerProtocolVersion: protocolVersion,
		SecurityToken: opcua.ChannelSecurityToken{
			ChannelID:       ch.channelID,
			TokenID:         ch.tokenID,
			CreatedAt:       time.Now(),
			RevisedLifetime: req.RequestedLifetime,
		},
		ServerNonce: opcua.ByteString(ch.localNonce),
	}
	ch.Write(res, requestid)
	// log.Printf("Renewed security token. %d , lifetime: %d\n", res.SecurityToken.TokenId, res.SecurityToken.RevisedLifetime)

	return nil
}

// getNextSequenceNumber gets next SequenceNumber in sequence, skipping zero.
func (ch *serverSecureChannel) getNextSequenceNumber() uint32 {
	ch.sequenceNumberLock.Lock()
	defer ch.sequenceNumberLock.Unlock()
	if ch.sequenceNumber == math.MaxUint32 {
		ch.sequenceNumber = 0
	}
	ch.sequenceNumber++
	return ch.sequenceNumber
}

// getNextTokenID gets next TokenID in sequence, skipping zero.
func (ch *serverSecureChannel) getNextTokenID() uint32 {
	atomic.CompareAndSwapUint32(&ch.tokenID, math.MaxUint32, 0)
	ch.tokenIDLock.Lock()
	defer ch.tokenIDLock.Unlock()
	if ch.tokenID == math.MaxUint32 {
		ch.tokenID = 0
	}
	ch.tokenID++
	return ch.tokenID
}

// getNextNonce gets next random nonce of requested length.
func getNextNonce(length int) []byte {
	var nonce = make([]byte, length)
	rand.Read(nonce)
	return nonce
}

// getNextServerChannelID gets next id in sequence, skipping zero.
func getNextServerChannelID() uint32 {
	channelIDLock.Lock()
	defer channelIDLock.Unlock()
	if channelID == math.MaxUint32 {
		channelID = 0
	}
	channelID++
	return channelID
}

// calculatePSHA calculates the pseudo random function.
func calculatePSHA(secret, seed []byte, sizeBytes int, securityPolicyURI string) []byte {
	var mac hash.Hash
	switch securityPolicyURI {
	case opcua.SecurityPolicyURIBasic128Rsa15, opcua.SecurityPolicyURIBasic256:
		mac = hmac.New(sha1.New, secret)

	default:
		mac = hmac.New(sha256.New, secret)
	}
	size := mac.Size()
	output := make([]byte, sizeBytes)
	a := seed
	iterations := (sizeBytes + size - 1) / size
	for i := 0; i < iterations; i++ {
		mac.Reset()
		mac.Write(a)
		buf := mac.Sum(nil)
		a = buf
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		buf2 := mac.Sum(nil)
		m := size * i
		n := sizeBytes - m
		if n > size {
			n = size
		}
		copy(output[m:m+n], buf2)
	}

	return output
}

func (ch *serverSecureChannel) setSecurityPolicy(securityPolicyURI string) error {
	if ch.securityPolicyURI == securityPolicyURI {
		// log.Printf("bypassed set %s\n", securityPolicyUri)
		return nil
	}
	ch.securityPolicyURI = securityPolicyURI
	switch securityPolicyURI {
	case opcua.SecurityPolicyURIBasic128Rsa15:
		if ch.LocalCertificate() == nil {
			return opcua.BadSecurityChecksFailed
		}

		if ch.LocalPrivateKey() == nil {
			return opcua.BadSecurityChecksFailed
		}

		if ch.remoteCertificate != nil && len(ch.remoteCertificate) > 0 {
			if crt, err := x509.ParseCertificate(ch.remoteCertificate); err == nil {
				ch.remotePublicKey = crt.PublicKey.(*rsa.PublicKey)
			}
		}

		if ch.remotePublicKey == nil {
			return opcua.BadSecurityChecksFailed
		}

		ch.asymSign = func(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
			hashed := sha1.Sum(plainText)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hashed[:])
		}
		ch.asymVerify = func(pub *rsa.PublicKey, plainText, signature []byte) error {
			hashed := sha1.Sum(plainText)
			return rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashed[:], signature)
		}
		ch.asymEncrypt = func(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
			return rsa.EncryptPKCS1v15(rand.Reader, pub, plainText)
		}
		ch.asymDecrypt = func(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
			return rsa.DecryptPKCS1v15(rand.Reader, priv, cipherText)
		}
		ch.symHMACFactory = func(key []byte) hash.Hash {
			return hmac.New(sha1.New, key)
		}
		ch.symSign = func(mac hash.Hash, plainText []byte) ([]byte, error) {
			mac.Reset()
			mac.Write(plainText)
			return mac.Sum(nil), nil
		}
		ch.symVerify = func(mac hash.Hash, plainText, signature []byte) error {
			mac.Reset()
			mac.Write(plainText)
			sig := mac.Sum(nil)
			if !hmac.Equal(sig, signature) {
				return opcua.BadSecurityChecksFailed
			}
			return nil
		}
		ch.asymLocalKeySize = len(ch.LocalPrivateKey().D.Bytes())
		ch.asymRemoteKeySize = len(ch.remotePublicKey.N.Bytes())
		ch.asymLocalPlainTextBlockSize = ch.asymLocalKeySize - 11
		ch.asymRemotePlainTextBlockSize = ch.asymRemoteKeySize - 11
		ch.asymLocalSignatureSize = ch.asymLocalKeySize
		ch.asymRemoteSignatureSize = ch.asymRemoteKeySize
		ch.asymLocalCipherTextBlockSize = ch.asymLocalKeySize
		ch.asymRemoteCipherTextBlockSize = ch.asymRemoteKeySize
		ch.symSignatureSize = 20
		ch.symSignatureKeySize = 16
		ch.symEncryptionBlockSize = 16
		ch.symEncryptionKeySize = 16

	case opcua.SecurityPolicyURIBasic256:

		if ch.LocalCertificate() == nil {
			return opcua.BadSecurityChecksFailed
		}

		if ch.LocalPrivateKey() == nil {
			return opcua.BadSecurityChecksFailed
		}

		if ch.remoteCertificate != nil && len(ch.remoteCertificate) > 0 {
			if crt, err := x509.ParseCertificate(ch.remoteCertificate); err == nil {
				ch.remotePublicKey = crt.PublicKey.(*rsa.PublicKey)
			}
		}

		if ch.remotePublicKey == nil {
			return opcua.BadSecurityChecksFailed
		}

		ch.asymSign = func(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
			hashed := sha1.Sum(plainText)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hashed[:])
		}
		ch.asymVerify = func(pub *rsa.PublicKey, plainText, signature []byte) error {
			hashed := sha1.Sum(plainText)
			return rsa.VerifyPKCS1v15(pub, crypto.SHA1, hashed[:], signature)
		}
		ch.asymEncrypt = func(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
			return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plainText, []byte{})
		}
		ch.asymDecrypt = func(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
			return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipherText, []byte{})
		}
		ch.symHMACFactory = func(key []byte) hash.Hash {
			return hmac.New(sha1.New, key)
		}
		ch.symSign = func(mac hash.Hash, plainText []byte) ([]byte, error) {
			mac.Reset()
			mac.Write(plainText)
			return mac.Sum(nil), nil
		}
		ch.symVerify = func(mac hash.Hash, plainText, signature []byte) error {
			mac.Reset()
			mac.Write(plainText)
			sig := mac.Sum(nil)
			if !hmac.Equal(sig, signature) {
				return opcua.BadSecurityChecksFailed
			}
			return nil
		}
		ch.asymLocalKeySize = len(ch.LocalPrivateKey().D.Bytes())
		ch.asymRemoteKeySize = len(ch.remotePublicKey.N.Bytes())
		ch.asymLocalPlainTextBlockSize = ch.asymLocalKeySize - 42
		ch.asymRemotePlainTextBlockSize = ch.asymRemoteKeySize - 42
		ch.asymLocalSignatureSize = ch.asymLocalKeySize
		ch.asymRemoteSignatureSize = ch.asymRemoteKeySize
		ch.asymLocalCipherTextBlockSize = ch.asymLocalKeySize
		ch.asymRemoteCipherTextBlockSize = ch.asymRemoteKeySize
		ch.symSignatureSize = 20
		ch.symSignatureKeySize = 24
		ch.symEncryptionBlockSize = 16
		ch.symEncryptionKeySize = 32

	case opcua.SecurityPolicyURIBasic256Sha256:

		if ch.LocalCertificate() == nil {
			return opcua.BadSecurityChecksFailed
		}

		if ch.LocalPrivateKey() == nil {
			return opcua.BadSecurityChecksFailed
		}

		if ch.remoteCertificate != nil && len(ch.remoteCertificate) > 0 {
			if crt, err := x509.ParseCertificate(ch.remoteCertificate); err == nil {
				ch.remotePublicKey = crt.PublicKey.(*rsa.PublicKey)
			}
		}

		if ch.remotePublicKey == nil {
			return opcua.BadSecurityChecksFailed
		}

		ch.asymSign = func(priv *rsa.PrivateKey, plainText []byte) ([]byte, error) {
			hashed := sha256.Sum256(plainText)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hashed[:])
		}
		ch.asymVerify = func(pub *rsa.PublicKey, plainText, signature []byte) error {
			hashed := sha256.Sum256(plainText)
			return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
		}
		ch.asymEncrypt = func(pub *rsa.PublicKey, plainText []byte) ([]byte, error) {
			return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, plainText, []byte{})
		}
		ch.asymDecrypt = func(priv *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
			return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cipherText, []byte{})
		}
		ch.symHMACFactory = func(key []byte) hash.Hash {
			return hmac.New(sha256.New, key)
		}
		ch.symSign = func(mac hash.Hash, plainText []byte) ([]byte, error) {
			mac.Reset()
			mac.Write(plainText)
			return mac.Sum(nil), nil
		}
		ch.symVerify = func(mac hash.Hash, plainText, signature []byte) error {
			mac.Reset()
			mac.Write(plainText)
			sig := mac.Sum(nil)
			if !hmac.Equal(sig, signature) {
				return opcua.BadSecurityChecksFailed
			}
			return nil
		}
		ch.asymLocalKeySize = len(ch.LocalPrivateKey().D.Bytes())
		ch.asymRemoteKeySize = len(ch.remotePublicKey.N.Bytes())
		ch.asymLocalPlainTextBlockSize = ch.asymLocalKeySize - 42
		ch.asymRemotePlainTextBlockSize = ch.asymRemoteKeySize - 42
		ch.asymLocalSignatureSize = ch.asymLocalKeySize
		ch.asymRemoteSignatureSize = ch.asymRemoteKeySize
		ch.asymLocalCipherTextBlockSize = ch.asymLocalKeySize
		ch.asymRemoteCipherTextBlockSize = ch.asymRemoteKeySize
		ch.symSignatureSize = 32
		ch.symSignatureKeySize = 32
		ch.symEncryptionBlockSize = 16
		ch.symEncryptionKeySize = 32

	case opcua.SecurityPolicyURINone:
		ch.asymLocalKeySize = 0
		ch.asymRemoteKeySize = 0
		ch.asymLocalPlainTextBlockSize = 1
		ch.asymRemotePlainTextBlockSize = 1
		ch.asymLocalSignatureSize = 0
		ch.asymRemoteSignatureSize = 0
		ch.asymLocalCipherTextBlockSize = 1
		ch.asymRemoteCipherTextBlockSize = 1
		ch.symSignatureSize = 0
		ch.symSignatureKeySize = 0
		ch.symEncryptionBlockSize = 1
		ch.symEncryptionKeySize = 0

	default:
		return opcua.BadSecurityPolicyRejected
	}

	return nil
}

// Read receives a chunk from the remote endpoint.
func (ch *serverSecureChannel) read(p []byte) (int, error) {
	if ch.conn == nil {
		// log.Println("Error in conn.Read() conn is nil")
		ch.closed = true
		return 0, opcua.BadSecureChannelClosed
	}

	var err error
	num := 0
	n := 0
	count := 8
	for num < count {
		n, err = ch.conn.Read(p[num:count])
		if err != nil || n == 0 {
			// log.Println("Error in conn.Read() " + err.Error())
			ch.conn.Close()
			ch.closed = true
			return num, err
		}
		num += n
	}

	count = int(binary.LittleEndian.Uint32(p[4:8]))
	for num < count {
		n, err = ch.conn.Read(p[num:count])
		if err != nil || n == 0 {
			// log.Println("Error in conn.Read() " + err.Error())
			ch.conn.Close()
			ch.closed = true
			return num, err
		}
		num += n
	}

	return num, err
}

// Write sends a chunk to the remote endpoint.
func (ch *serverSecureChannel) write(p []byte) (int, error) {
	if ch.conn == nil {
		// log.Println("Error in conn.Write() conn is nil")
		ch.closed = true
		return 0, opcua.BadSecureChannelClosed
	}
	n, err := ch.conn.Write(p)
	if err != nil || n == 0 {
		// log.Println("Error in conn.Write() " + err.Error())
		ch.conn.Close()
		ch.closed = true
	}
	return n, err
}
