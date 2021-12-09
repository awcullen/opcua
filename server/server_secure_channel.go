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

	"github.com/awcullen/opcua/ua"
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
	securityMode                ua.MessageSecurityMode
	remoteCertificateThumbprint []byte
	localEndpoint               ua.EndpointDescription
	discoveryOnly               bool
	wg                          sync.WaitGroup
	sendingSemaphore            sync.Mutex
	receivingSemaphore          sync.Mutex
	responseCh                  chan struct {
		ua.ServiceResponse
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
func (ch *serverSecureChannel) LocalDescription() ua.ApplicationDescription {
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
func (ch *serverSecureChannel) LocalEndpoint() ua.EndpointDescription {
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
func (ch *serverSecureChannel) SecurityMode() ua.MessageSecurityMode {
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
func (ch *serverSecureChannel) Abort(reason ua.StatusCode, message string) error {
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
func (ch *serverSecureChannel) Write(res ua.ServiceResponse, id uint32) error {
	if ch.trace {
		b, _ := json.MarshalIndent(res, "", " ")
		log.Printf("%s%s", reflect.TypeOf(res).Elem().Name(), b)
	}
	switch res1 := res.(type) {
	case *ua.OpenSecureChannelResponse:
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
		return ua.BadDecodingError
	}

	var reader = bytes.NewReader(buf)
	var ec = ua.NewEncodingContext()
	var dec = ua.NewBinaryDecoder(reader, ec)

	var msgType uint32
	if err := dec.ReadUInt32(&msgType); err != nil {
		return ua.BadDecodingError
	}
	var msgLen uint32
	if err := dec.ReadUInt32(&msgLen); err != nil {
		return ua.BadDecodingError
	}

	var remoteProtocolVersion, remoteReceiveBufferSize, remoteSendBufferSize, remoteMaxMessageSize, remoteMaxChunkCount uint32
	switch msgType {
	case ua.MessageTypeHello:
		if msgLen < 28 {
			return ua.BadDecodingError
		}
		if err != nil {
			return ua.BadDecodingError
		}
		if err = dec.ReadUInt32(&remoteProtocolVersion); err != nil || remoteProtocolVersion < protocolVersion {
			return ua.BadProtocolVersionUnsupported
		}
		if err = dec.ReadUInt32(&remoteReceiveBufferSize); err != nil {
			return ua.BadDecodingError
		}
		if err = dec.ReadUInt32(&remoteSendBufferSize); err != nil {
			return ua.BadDecodingError
		}
		if err = dec.ReadUInt32(&remoteMaxMessageSize); err != nil {
			return ua.BadDecodingError
		}
		if err = dec.ReadUInt32(&remoteMaxChunkCount); err != nil {
			return ua.BadDecodingError
		}
		if err := dec.ReadString(&ch.endpointURL); err != nil {
			return ua.BadDecodingError
		}
		// log.Printf("-> Hello { ver: %d, rec: %d, snd: %d, msg: %d, chk: %d, ep: %s }\n", remoteProtocolVersion, ch.remoteReceiveBufferSize, ch.remoteSendBufferSize, ch.remoteMaxMessageSize, ch.remoteMaxChunkCount, ch.endpointUrl)

	default:
		return ua.BadDecodingError
	}

	var writer = ua.NewWriter(buf)
	var enc = ua.NewBinaryEncoder(writer, ec)

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
	enc.WriteUInt32(ua.MessageTypeAck)
	enc.WriteUInt32(uint32(28))
	enc.WriteUInt32(protocolVersion)
	enc.WriteUInt32(ch.receiveBufferSize)
	enc.WriteUInt32(ch.sendBufferSize)
	enc.WriteUInt32(ch.maxMessageSize)
	enc.WriteUInt32(ch.maxChunkCount)
	_, err = ch.write(writer.Bytes())
	if err != nil {
		// log.Printf("Error opening Transport Channel: %s \n", err.Error())
		return ua.BadEncodingError
	}
	// log.Printf("<- Ack { ver: %d, rec: %d, snd: %d, msg: %d, chk: %d, ep: %s }\n", serverProtocolVersion, ch.localReceiveBufferSize, ch.localSendBufferSize, ch.localMaxMessageSize, ch.localMaxChunkCount, ch.conn.RemoteAddr())

	ch.sendBuffer = make([]byte, ch.sendBufferSize)
	ch.receiveBuffer = make([]byte, ch.receiveBufferSize)
	ch.encryptionBuffer = make([]byte, ch.sendBufferSize)
	ch.tokenID = 0
	ch.sendingTokenID = 0
	ch.receivingTokenID = 0
	ch.responseCh = make(chan struct {
		ua.ServiceResponse
		uint32
	}, 32)
	ch.setSecurityPolicy(ua.SecurityPolicyURINone)

	// read first request, which must be an OpenSecureChannelRequest
	req, rid, err := ch.readRequest()
	if err != nil {
		log.Printf("Error receiving OpenSecureChannelRequest. %s\n", err)
		return err
	}
	oscr, ok := req.(*ua.OpenSecureChannelRequest)
	if !ok {
		return ua.BadDecodingError
	}
	ch.tokenLock.Lock()
	ch.tokenID = ch.getNextTokenID()
	ch.securityMode = oscr.SecurityMode
	if ch.securityMode != ua.MessageSecurityModeNone {
		ch.localNonce = getNextNonce(int(ch.symEncryptionKeySize))
	} else {
		ch.localNonce = []byte{}
	}
	ch.remoteNonce = []byte(oscr.ClientNonce)
	ch.tokenLock.Unlock()
	for _, ep := range ch.srv.Endpoints() {
		if ep.TransportProfileURI == ua.TransportProfileURIUaTcpTransport && ep.SecurityPolicyURI == ch.securityPolicyURI && ep.SecurityMode == ch.securityMode {
			ch.localEndpoint = ep
			break
		}
	}
	// connecting for discovery only
	if ch.localEndpoint.EndpointURL == "" && ch.securityPolicyURI == ua.SecurityPolicyURINone && ch.securityMode == ua.MessageSecurityModeNone {
		ch.discoveryOnly = true
		ch.localEndpoint = ua.EndpointDescription{
			EndpointURL:       ch.srv.localDescription.DiscoveryURLs[0],
			Server:            ch.srv.localDescription,
			SecurityMode:      ua.MessageSecurityModeNone,
			SecurityPolicyURI: ua.SecurityPolicyURINone,
			UserIdentityTokens: []ua.UserTokenPolicy{
				{
					PolicyID:          "Anonymous",
					TokenType:         ua.UserTokenTypeAnonymous,
					SecurityPolicyURI: ua.SecurityPolicyURINone,
				},
			},
			TransportProfileURI: ua.TransportProfileURIUaTcpTransport,
			SecurityLevel:       0,
		}
	}

	if ch.securityMode != ua.MessageSecurityModeNone {
		rc := ch.remoteCertificate
		if rc == nil {
			return ua.BadSecurityChecksFailed
		}
		cert, err := x509.ParseCertificate(ch.remoteCertificate)
		if err != nil {
			return ua.BadSecurityChecksFailed
		}
		valid, err := validateClientCertificate(cert, ch.srv.trustedCertsPath, ch.srv.suppressCertificateExpired, ch.srv.suppressCertificateChainIncomplete)
		if !valid {
			return err
		}
		if len(cert.URIs) > 0 {
			ch.remoteApplicationURI = cert.URIs[0].String()
		}
	}
	res := &ua.OpenSecureChannelResponse{
		ResponseHeader: ua.ResponseHeader{
			Timestamp:     time.Now(),
			RequestHandle: oscr.Header().RequestHandle,
		},
		ServerProtocolVersion: protocolVersion,
		SecurityToken: ua.ChannelSecurityToken{
			ChannelID:       ch.channelID,
			TokenID:         ch.tokenID,
			CreatedAt:       time.Now(),
			RevisedLifetime: oscr.RequestedLifetime,
		},
		ServerNonce: ua.ByteString(ch.localNonce),
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

func (ch *serverSecureChannel) onAbort(reason ua.StatusCode, message string) error {
	// log.Printf("onAbort secure channel.\n")
	if ch.conn != nil {
		buf := *(bytesPool.Get().(*[]byte))
		defer bytesPool.Put(&buf)
		var writer = ua.NewWriter(buf)
		var ec = ua.NewEncodingContext()
		var enc = ua.NewBinaryEncoder(writer, ec)
		enc.WriteUInt32(ua.MessageTypeError)
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
func (ch *serverSecureChannel) sendOpenSecureChannelResponse(res *ua.OpenSecureChannelResponse, id uint32) error {
	ch.sendingSemaphore.Lock()
	defer ch.sendingSemaphore.Unlock()
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()
	var bodyEncoder = ua.NewBinaryEncoder(bodyStream, ch)

	if err := bodyEncoder.WriteNodeID(ua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary); err != nil {
		return ua.BadEncodingError
	}

	if err := bodyEncoder.Encode(res); err != nil {
		return ua.BadEncodingError
	}

	if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
		return ua.BadEncodingLimitsExceeded
	}

	// write chunks
	var chunkCount int
	var bodyCount = int(bodyStream.Len())

	for bodyCount > 0 {
		chunkCount++
		if i := int(ch.maxChunkCount); i > 0 && chunkCount > i {
			return ua.BadEncodingLimitsExceeded
		}

		// plan
		var plainHeaderSize int
		var paddingHeaderSize int
		var maxBodySize int
		var bodySize int
		var paddingSize int
		var chunkSize int
		if ch.securityMode != ua.MessageSecurityModeNone {
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

		var stream = ua.NewWriter(ch.sendBuffer)
		var encoder = ua.NewBinaryEncoder(stream, ch)

		// header
		encoder.WriteUInt32(ua.MessageTypeOpenFinal)
		encoder.WriteUInt32(uint32(chunkSize))
		encoder.WriteUInt32(ch.channelID)

		// asymmetric security header
		encoder.WriteString(ch.securityPolicyURI)
		if ch.securityMode != ua.MessageSecurityModeNone {
			encoder.WriteByteArray(ch.LocalCertificate())
			thumbprint := sha1.Sum(ch.remoteCertificate)
			encoder.WriteByteArray(thumbprint[:])
		} else {
			encoder.WriteByteArray(nil)
			encoder.WriteByteArray(nil)
		}

		if plainHeaderSize != stream.Len() {
			return ua.BadEncodingError
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
		if ch.securityMode != ua.MessageSecurityModeNone {
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
			return ua.BadEncodingError
		}

		// sign
		if ch.securityMode != ua.MessageSecurityModeNone {
			signature, err := ch.asymSign(ch.LocalPrivateKey(), stream.Bytes())
			if err != nil {
				return err
			}
			if len(signature) != ch.asymLocalSignatureSize {
				return ua.BadEncodingError
			}
			_, err = stream.Write(signature)
			if err != nil {
				return err
			}
		}

		// encrypt
		if ch.securityMode != ua.MessageSecurityModeNone {
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
					return ua.BadEncodingError
				}
				copy(ch.encryptionBuffer[jj:], cipherText)
				jj += ch.asymRemoteCipherTextBlockSize
			}
			if jj != chunkSize {
				return ua.BadEncodingError
			}
			// pass buffer to transport
			_, err := ch.write(ch.encryptionBuffer[:chunkSize])
			if err != nil {
				return err
			}

		} else {

			if stream.Len() != chunkSize {
				return ua.BadEncodingError
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
func (ch *serverSecureChannel) sendServiceResponse(response ua.ServiceResponse, id uint32) error {
	ch.sendingSemaphore.Lock()
	defer ch.sendingSemaphore.Unlock()
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()
	var bodyEncoder = ua.NewBinaryEncoder(bodyStream, ch)

	switch res := response.(type) {

	// frequent
	case *ua.PublishResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDPublishResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.ReadResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDReadResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.BrowseResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDBrowseResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.BrowseNextResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDBrowseNextResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.TranslateBrowsePathsToNodeIDsResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDTranslateBrowsePathsToNodeIDsResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.WriteResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDWriteResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CallResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCallResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.HistoryReadResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDHistoryReadResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}

	// moderate
	case *ua.GetEndpointsResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDGetEndpointsResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.OpenSecureChannelResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDOpenSecureChannelResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CloseSecureChannelResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCloseSecureChannelResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CreateSessionResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCreateSessionResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.ActivateSessionResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDActivateSessionResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CloseSessionResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCloseSessionResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CreateMonitoredItemsResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCreateMonitoredItemsResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.DeleteMonitoredItemsResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDDeleteMonitoredItemsResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CreateSubscriptionResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCreateSubscriptionResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.DeleteSubscriptionsResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDDeleteSubscriptionsResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.SetPublishingModeResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDSetPublishingModeResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.ServiceFault:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDServiceFaultEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}

		// rare
	case *ua.ModifyMonitoredItemsResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDModifyMonitoredItemsResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.SetMonitoringModeResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDSetMonitoringModeResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.SetTriggeringResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDSetTriggeringResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.ModifySubscriptionResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDModifySubscriptionResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.RepublishResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDRepublishResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.TransferSubscriptionsResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDTransferSubscriptionsResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.FindServersResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDFindServersResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.FindServersOnNetworkResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDFindServersOnNetworkResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.RegisterServerResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDRegisterServerResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.RegisterServer2Response:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDRegisterServer2ResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.CancelResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDCancelResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.AddNodesResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDAddNodesResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.AddReferencesResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDAddReferencesResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.DeleteNodesResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDDeleteNodesResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.DeleteReferencesResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDDeleteReferencesResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.RegisterNodesResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDRegisterNodesResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.UnregisterNodesResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDUnregisterNodesResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.QueryFirstResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDQueryFirstResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.QueryNextResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDQueryNextResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	case *ua.HistoryUpdateResponse:
		if err := bodyEncoder.WriteNodeID(ua.ObjectIDHistoryUpdateResponseEncodingDefaultBinary); err != nil {
			return ua.BadEncodingError
		}
		if err := bodyEncoder.Encode(res); err != nil {
			return ua.BadEncodingError
		}
	default:
		return ua.BadEncodingError
	}

	if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
		return ua.BadEncodingLimitsExceeded
	}

	var chunkCount int
	var bodyCount = int(bodyStream.Len())

	for bodyCount > 0 {
		chunkCount++
		if i := int(ch.maxChunkCount); i > 0 && chunkCount > i {
			return ua.BadEncodingLimitsExceeded
		}

		// plan
		var plainHeaderSize int
		var paddingHeaderSize int
		var maxBodySize int
		var bodySize int
		var paddingSize int
		var chunkSize int
		if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
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

		var stream = ua.NewWriter(ch.sendBuffer)
		var encoder = ua.NewBinaryEncoder(stream, ch)

		// header
		if bodyCount > bodySize {
			encoder.WriteUInt32(ua.MessageTypeChunk)
		} else {
			encoder.WriteUInt32(ua.MessageTypeFinal)
		}
		encoder.WriteUInt32(uint32(chunkSize))
		encoder.WriteUInt32(ch.channelID)

		// symmetric security header
		encoder.WriteUInt32(ch.sendingTokenID)

		if plainHeaderSize != stream.Len() {
			return ua.BadEncodingError
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
		if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
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
		if ch.securityMode != ua.MessageSecurityModeNone {
			signature, err := ch.symSign(ch.symSignHMAC, stream.Bytes())
			if err != nil {
				return err
			}
			stream.Write(signature)
		}

		// encrypt
		if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
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
func (ch *serverSecureChannel) readRequest() (ua.ServiceRequest, uint32, error) {
	ch.receivingSemaphore.Lock()
	defer ch.receivingSemaphore.Unlock()
	var req ua.ServiceRequest
	var id uint32
	var plainHeaderSize int
	var paddingHeaderSize int
	var bodySize int
	var paddingSize int
	var channelID uint32
	var tokenID uint32
	var bodyStream = buffer.NewPartitionAt(bufferPool)
	defer bodyStream.Reset()
	var bodyDecoder = ua.NewBinaryDecoder(bodyStream, ch)

	// read chunks
	var chunkCount int32
	var isFinal bool

	for !isFinal {
		chunkCount++
		if i := int32(ch.maxChunkCount); i > 0 && chunkCount > i {
			return nil, 0, ua.BadEncodingLimitsExceeded
		}

		count, err := ch.read(ch.receiveBuffer)
		if err != nil || count == 0 {
			return nil, 0, ua.BadSecureChannelClosed
		}

		var stream = bytes.NewReader(ch.receiveBuffer[0:count])
		var decoder = ua.NewBinaryDecoder(stream, ch)

		var messageType uint32
		if err := decoder.ReadUInt32(&messageType); err != nil {
			return nil, 0, err
		}
		var messageLength uint32
		if err := decoder.ReadUInt32(&messageLength); err != nil {
			return nil, 0, err
		}

		if count != int(messageLength) {
			return nil, 0, ua.BadDecodingError
		}

		switch messageType {
		case ua.MessageTypeChunk, ua.MessageTypeFinal, ua.MessageTypeCloseFinal:

			// header
			if err := decoder.ReadUInt32(&channelID); err != nil {
				return nil, 0, ua.BadDecodingError
			}
			if channelID != ch.channelID {
				return nil, 0, ua.BadTCPSecureChannelUnknown
			}

			// symmetric security header
			if err = decoder.ReadUInt32(&tokenID); err != nil {
				return nil, 0, ua.BadDecodingError
			}

			// detect new token
			ch.tokenLock.RLock()
			if ch.receivingTokenID != tokenID {
				ch.receivingTokenID = tokenID

				if ch.securityMode != ua.MessageSecurityModeNone {
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
					if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
						if cipher, err := aes.NewCipher(ch.remoteEncryptingKey); err == nil {
							ch.symDecryptingBlockCipher = cipher
						} else {
							ch.tokenLock.RUnlock()
							return nil, 0, ua.BadDecodingError
						}
					}
				}

				ch.sendingTokenID = tokenID
				if ch.securityMode != ua.MessageSecurityModeNone {

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
					if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
						if cipher, err := aes.NewCipher(ch.localEncryptingKey); err == nil {
							ch.symEncryptingBlockCipher = cipher
						} else {
							ch.tokenLock.RUnlock()
							return nil, 0, ua.BadDecodingError
						}
					}
				}

				// log.Printf("Installed security token. %d\n", ch.sendingTokenId)
			}
			ch.tokenLock.RUnlock()

			plainHeaderSize = 16
			// decrypt
			if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
				span := ch.receiveBuffer[plainHeaderSize:count]
				if len(span)%ch.symDecryptingBlockCipher.BlockSize() != 0 {
					return nil, 0, ua.BadEncodingError
				}
				symDecryptor := cipher.NewCBCDecrypter(ch.symDecryptingBlockCipher, ch.remoteInitializationVector)
				symDecryptor.CryptBlocks(span, span)
			}

			// verify
			if ch.securityMode != ua.MessageSecurityModeNone {
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
				return nil, 0, ua.BadDecodingError
			}

			if err = decoder.ReadUInt32(&id); err != nil {
				return nil, 0, ua.BadDecodingError
			}

			// body
			if ch.securityMode == ua.MessageSecurityModeSignAndEncrypt {
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
			isFinal = messageType != ua.MessageTypeChunk

		case ua.MessageTypeOpenFinal:
			// header
			if err = decoder.ReadUInt32(&channelID); err != nil {
				return nil, 0, ua.BadDecodingError
			}
			// asymmetric header
			var securityPolicyURI string
			if err := decoder.ReadString(&securityPolicyURI); err != nil {
				return nil, 0, ua.BadDecodingError
			}
			if err := decoder.ReadByteArray(&ch.remoteCertificate); err != nil {
				return nil, 0, ua.BadDecodingError
			}
			if err := decoder.ReadByteArray(&ch.remoteCertificateThumbprint); err != nil {
				return nil, 0, ua.BadDecodingError
			}
			plainHeaderSize = count - stream.Len()

			err = ch.setSecurityPolicy(securityPolicyURI)
			if err != nil {
				return nil, 0, ua.BadDecodingError
			}

			// decrypt
			if ch.securityPolicyURI != ua.SecurityPolicyURINone {

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
						return nil, 0, ua.BadEncodingError
					}
					copy(ch.receiveBuffer[jj:], plainText)
					jj += ch.asymLocalPlainTextBlockSize
				}

				messageLength = uint32(jj) // msg is shorter after decryption

			}

			// verify
			if ch.securityPolicyURI != ua.SecurityPolicyURINone {
				// verify with remote public key.
				sigEnd := int(messageLength)
				sigStart := sigEnd - ch.asymRemoteSignatureSize
				err := ch.asymVerify(ch.remotePublicKey, ch.receiveBuffer[:sigStart], ch.receiveBuffer[sigStart:sigEnd])
				if err != nil {
					return nil, 0, ua.BadDecodingError
				}
			}

			// sequence header
			var unused uint32
			if err := decoder.ReadUInt32(&unused); err != nil {
				return nil, 0, ua.BadDecodingError
			}

			if err := decoder.ReadUInt32(&id); err != nil {
				return nil, 0, ua.BadDecodingError
			}

			// body
			if ch.securityPolicyURI != ua.SecurityPolicyURINone {
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

			isFinal = messageType == ua.MessageTypeOpenFinal

		case ua.MessageTypeError, ua.MessageTypeAbort:
			var statusCode uint32
			if err := decoder.ReadUInt32(&statusCode); err != nil {
				return nil, 0, ua.BadDecodingError
			}
			var message string
			if err := decoder.ReadString(&message); err != nil {
				return nil, 0, ua.BadDecodingError
			}
			log.Printf("Server sent error response. %s %s\n", ua.StatusCode(statusCode).Error(), message)
			return nil, 0, ua.StatusCode(statusCode)

		default:
			return nil, 0, ua.BadUnknownResponse
		}

		if i := int64(ch.maxMessageSize); i > 0 && bodyStream.Len() > i {
			return nil, 0, ua.BadEncodingLimitsExceeded
		}
	}

	var nodeID ua.NodeID
	if err := bodyDecoder.ReadNodeID(&nodeID); err != nil {
		return nil, 0, ua.BadDecodingError
	}
	var temp interface{}
	switch nodeID {

	// frequent
	case ua.ObjectIDPublishRequestEncodingDefaultBinary:
		temp = new(ua.PublishRequest)
	case ua.ObjectIDReadRequestEncodingDefaultBinary:
		temp = new(ua.ReadRequest)
	case ua.ObjectIDBrowseRequestEncodingDefaultBinary:
		temp = new(ua.BrowseRequest)
	case ua.ObjectIDBrowseNextRequestEncodingDefaultBinary:
		temp = new(ua.BrowseNextRequest)
	case ua.ObjectIDTranslateBrowsePathsToNodeIDsRequestEncodingDefaultBinary:
		temp = new(ua.TranslateBrowsePathsToNodeIDsRequest)
	case ua.ObjectIDWriteRequestEncodingDefaultBinary:
		temp = new(ua.WriteRequest)
	case ua.ObjectIDCallRequestEncodingDefaultBinary:
		temp = new(ua.CallRequest)
	case ua.ObjectIDHistoryReadRequestEncodingDefaultBinary:
		temp = new(ua.HistoryReadRequest)

	// moderate
	case ua.ObjectIDGetEndpointsRequestEncodingDefaultBinary:
		temp = new(ua.GetEndpointsRequest)
	case ua.ObjectIDOpenSecureChannelRequestEncodingDefaultBinary:
		temp = new(ua.OpenSecureChannelRequest)
	case ua.ObjectIDCloseSecureChannelRequestEncodingDefaultBinary:
		temp = new(ua.CloseSecureChannelRequest)
	case ua.ObjectIDCreateSessionRequestEncodingDefaultBinary:
		temp = new(ua.CreateSessionRequest)
	case ua.ObjectIDActivateSessionRequestEncodingDefaultBinary:
		temp = new(ua.ActivateSessionRequest)
	case ua.ObjectIDCloseSessionRequestEncodingDefaultBinary:
		temp = new(ua.CloseSessionRequest)
	case ua.ObjectIDCreateMonitoredItemsRequestEncodingDefaultBinary:
		temp = new(ua.CreateMonitoredItemsRequest)
	case ua.ObjectIDDeleteMonitoredItemsRequestEncodingDefaultBinary:
		temp = new(ua.DeleteMonitoredItemsRequest)
	case ua.ObjectIDCreateSubscriptionRequestEncodingDefaultBinary:
		temp = new(ua.CreateSubscriptionRequest)
	case ua.ObjectIDDeleteSubscriptionsRequestEncodingDefaultBinary:
		temp = new(ua.DeleteSubscriptionsRequest)
	case ua.ObjectIDSetPublishingModeRequestEncodingDefaultBinary:
		temp = new(ua.SetPublishingModeRequest)

		// rare
	case ua.ObjectIDModifyMonitoredItemsRequestEncodingDefaultBinary:
		temp = new(ua.ModifyMonitoredItemsRequest)
	case ua.ObjectIDSetMonitoringModeRequestEncodingDefaultBinary:
		temp = new(ua.SetMonitoringModeRequest)
	case ua.ObjectIDSetTriggeringRequestEncodingDefaultBinary:
		temp = new(ua.SetTriggeringRequest)
	case ua.ObjectIDModifySubscriptionRequestEncodingDefaultBinary:
		temp = new(ua.ModifySubscriptionRequest)
	case ua.ObjectIDRepublishRequestEncodingDefaultBinary:
		temp = new(ua.RepublishRequest)
	case ua.ObjectIDTransferSubscriptionsRequestEncodingDefaultBinary:
		temp = new(ua.TransferSubscriptionsRequest)
	case ua.ObjectIDFindServersRequestEncodingDefaultBinary:
		temp = new(ua.FindServersRequest)
	case ua.ObjectIDFindServersOnNetworkRequestEncodingDefaultBinary:
		temp = new(ua.FindServersOnNetworkRequest)
	case ua.ObjectIDRegisterServerRequestEncodingDefaultBinary:
		temp = new(ua.RegisterServerRequest)
	case ua.ObjectIDRegisterServer2RequestEncodingDefaultBinary:
		temp = new(ua.RegisterServer2Request)
	case ua.ObjectIDCancelRequestEncodingDefaultBinary:
		temp = new(ua.CancelRequest)
	case ua.ObjectIDAddNodesRequestEncodingDefaultBinary:
		temp = new(ua.AddNodesRequest)
	case ua.ObjectIDAddReferencesRequestEncodingDefaultBinary:
		temp = new(ua.AddReferencesRequest)
	case ua.ObjectIDDeleteNodesRequestEncodingDefaultBinary:
		temp = new(ua.DeleteNodesRequest)
	case ua.ObjectIDDeleteReferencesRequestEncodingDefaultBinary:
		temp = new(ua.DeleteReferencesRequest)
	case ua.ObjectIDRegisterNodesRequestEncodingDefaultBinary:
		temp = new(ua.RegisterNodesRequest)
	case ua.ObjectIDUnregisterNodesRequestEncodingDefaultBinary:
		temp = new(ua.UnregisterNodesRequest)
	case ua.ObjectIDQueryFirstRequestEncodingDefaultBinary:
		temp = new(ua.QueryFirstRequest)
	case ua.ObjectIDQueryNextRequestEncodingDefaultBinary:
		temp = new(ua.QueryNextRequest)
	case ua.ObjectIDHistoryUpdateRequestEncodingDefaultBinary:
		temp = new(ua.HistoryUpdateRequest)
	default:
		return nil, 0, ua.BadDecodingError
	}

	// decode fields from message stream
	if err := bodyDecoder.Decode(temp); err != nil {
		return nil, 0, ua.BadDecodingError
	}
	req = temp.(ua.ServiceRequest)

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
			if err != ua.BadSecureChannelClosed {
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
func (ch *serverSecureChannel) handleRequest(req ua.ServiceRequest, requestid uint32) error {
	switch req := req.(type) {
	case *ua.PublishRequest:
		return ch.srv.handlePublish(ch, requestid, req)
	case *ua.RepublishRequest:
		return ch.srv.handleRepublish(ch, requestid, req)
	case *ua.ReadRequest:
		return ch.srv.handleRead(ch, requestid, req)
	case *ua.WriteRequest:
		return ch.srv.handleWrite(ch, requestid, req)
	case *ua.CallRequest:
		return ch.srv.handleCall(ch, requestid, req)
	case *ua.BrowseRequest:
		return ch.srv.handleBrowse(ch, requestid, req)
	case *ua.BrowseNextRequest:
		return ch.srv.handleBrowseNext(ch, requestid, req)
	case *ua.TranslateBrowsePathsToNodeIDsRequest:
		return ch.srv.handleTranslateBrowsePathsToNodeIds(ch, requestid, req)
	case *ua.CreateSubscriptionRequest:
		return ch.srv.handleCreateSubscription(ch, requestid, req)
	case *ua.ModifySubscriptionRequest:
		return ch.srv.handleModifySubscription(ch, requestid, req)
	case *ua.SetPublishingModeRequest:
		return ch.srv.handleSetPublishingMode(ch, requestid, req)
	case *ua.DeleteSubscriptionsRequest:
		return ch.srv.handleDeleteSubscriptions(ch, requestid, req)
	case *ua.CreateMonitoredItemsRequest:
		return ch.srv.handleCreateMonitoredItems(ch, requestid, req)
	case *ua.ModifyMonitoredItemsRequest:
		return ch.srv.handleModifyMonitoredItems(ch, requestid, req)
	case *ua.SetMonitoringModeRequest:
		return ch.srv.handleSetMonitoringMode(ch, requestid, req)
	case *ua.DeleteMonitoredItemsRequest:
		return ch.srv.handleDeleteMonitoredItems(ch, requestid, req)
	case *ua.HistoryReadRequest:
		return ch.srv.handleHistoryRead(ch, requestid, req)
	case *ua.CreateSessionRequest:
		return ch.srv.handleCreateSession(ch, requestid, req)
	case *ua.ActivateSessionRequest:
		return ch.srv.handleActivateSession(ch, requestid, req)
	case *ua.CloseSessionRequest:
		return ch.srv.handleCloseSession(ch, requestid, req)
	case *ua.OpenSecureChannelRequest:
		return ch.handleOpenSecureChannel(requestid, req)
	case *ua.CloseSecureChannelRequest:
		return ch.srv.handleCloseSecureChannel(ch, requestid, req)
	case *ua.FindServersRequest:
		return ch.srv.findServers(ch, requestid, req)
	case *ua.GetEndpointsRequest:
		return ch.srv.getEndpoints(ch, requestid, req)
	case *ua.RegisterNodesRequest:
		return ch.srv.handleRegisterNodes(ch, requestid, req)
	case *ua.UnregisterNodesRequest:
		return ch.srv.handleUnregisterNodes(ch, requestid, req)
	case *ua.SetTriggeringRequest:
		return ch.srv.handleSetTriggering(ch, requestid, req)
	case *ua.CancelRequest:
		return ch.srv.handleCancel(ch, requestid, req)

	default:
		ch.Write(
			&ua.ServiceFault{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.Header().RequestHandle,
					ServiceResult: ua.BadServiceUnsupported,
				},
			},
			requestid,
		)
		return nil
	}
}

func (ch *serverSecureChannel) handleOpenSecureChannel(requestid uint32, req *ua.OpenSecureChannelRequest) error {
	if req.RequestType == ua.SecurityTokenRequestTypeIssue {
		return ua.BadSecurityChecksFailed
	}
	// handle renew token
	ch.tokenLock.Lock()
	ch.tokenID = ch.getNextTokenID()
	if ch.securityMode != ua.MessageSecurityModeNone {
		ch.localNonce = getNextNonce(int(ch.symEncryptionKeySize))
	} else {
		ch.localNonce = []byte{}
	}
	ch.remoteNonce = []byte(req.ClientNonce)
	ch.tokenLock.Unlock()
	res := &ua.OpenSecureChannelResponse{
		ResponseHeader: ua.ResponseHeader{
			Timestamp:     time.Now(),
			RequestHandle: req.Header().RequestHandle,
		},
		ServerProtocolVersion: protocolVersion,
		SecurityToken: ua.ChannelSecurityToken{
			ChannelID:       ch.channelID,
			TokenID:         ch.tokenID,
			CreatedAt:       time.Now(),
			RevisedLifetime: req.RequestedLifetime,
		},
		ServerNonce: ua.ByteString(ch.localNonce),
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
	case ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256:
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
	case ua.SecurityPolicyURIBasic128Rsa15:
		if ch.LocalCertificate() == nil {
			return ua.BadSecurityChecksFailed
		}

		if ch.LocalPrivateKey() == nil {
			return ua.BadSecurityChecksFailed
		}

		if ch.remoteCertificate != nil && len(ch.remoteCertificate) > 0 {
			if crt, err := x509.ParseCertificate(ch.remoteCertificate); err == nil {
				ch.remotePublicKey = crt.PublicKey.(*rsa.PublicKey)
			}
		}

		if ch.remotePublicKey == nil {
			return ua.BadSecurityChecksFailed
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
				return ua.BadSecurityChecksFailed
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

	case ua.SecurityPolicyURIBasic256:

		if ch.LocalCertificate() == nil {
			return ua.BadSecurityChecksFailed
		}

		if ch.LocalPrivateKey() == nil {
			return ua.BadSecurityChecksFailed
		}

		if ch.remoteCertificate != nil && len(ch.remoteCertificate) > 0 {
			if crt, err := x509.ParseCertificate(ch.remoteCertificate); err == nil {
				ch.remotePublicKey = crt.PublicKey.(*rsa.PublicKey)
			}
		}

		if ch.remotePublicKey == nil {
			return ua.BadSecurityChecksFailed
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
				return ua.BadSecurityChecksFailed
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

	case ua.SecurityPolicyURIBasic256Sha256:

		if ch.LocalCertificate() == nil {
			return ua.BadSecurityChecksFailed
		}

		if ch.LocalPrivateKey() == nil {
			return ua.BadSecurityChecksFailed
		}

		if ch.remoteCertificate != nil && len(ch.remoteCertificate) > 0 {
			if crt, err := x509.ParseCertificate(ch.remoteCertificate); err == nil {
				ch.remotePublicKey = crt.PublicKey.(*rsa.PublicKey)
			}
		}

		if ch.remotePublicKey == nil {
			return ua.BadSecurityChecksFailed
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
				return ua.BadSecurityChecksFailed
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

	case ua.SecurityPolicyURINone:
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
		return ua.BadSecurityPolicyRejected
	}

	return nil
}

// Read receives a chunk from the remote endpoint.
func (ch *serverSecureChannel) read(p []byte) (int, error) {
	if ch.conn == nil {
		// log.Println("Error in conn.Read() conn is nil")
		ch.closed = true
		return 0, ua.BadSecureChannelClosed
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
		return 0, ua.BadSecureChannelClosed
	}
	n, err := ch.conn.Write(p)
	if err != nil || n == 0 {
		// log.Println("Error in conn.Write() " + err.Error())
		ch.conn.Close()
		ch.closed = true
	}
	return n, err
}
