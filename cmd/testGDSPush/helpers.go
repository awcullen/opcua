package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
	"math/big"
	"net"
	"net/url"
	"os"
	"time"
)

func createNewCertificate(appName, certFile, keyFile, crlFile string) error {

	// create a keypair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	// get local hostname.
	host, _ := os.Hostname()

	// get local ip address.
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ua.BadCertificateInvalid
	}
	conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	// create a certificate.
	applicationURI, _ := url.Parse(fmt.Sprintf("urn:%s:%s", host, appName))
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subjectKeyHash := sha1.New()
	subjectKeyHash.Write(key.PublicKey.N.Bytes())
	subjectKeyId := subjectKeyHash.Sum(nil)
	oidDC := asn1.ObjectIdentifier([]int{0, 9, 2342, 19200300, 100, 1, 25})

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: appName, ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidDC, Value: host}}},
		SubjectKeyId:          subjectKeyId,
		AuthorityKeyId:        subjectKeyId,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host, "localhost"},
		IPAddresses:           []net.IP{localAddr.IP, []byte{127, 0, 0, 1}},
		URIs:                  []*url.URL{applicationURI},
		IsCA:                  true, // Added for signing the CRL
	}

	rawcrt, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	if f, err := os.Create(certFile); err == nil {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: rawcrt}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	// Also create empty revocation list
	crlCert, err := x509.ParseCertificate(rawcrt)
	crlTemplate := x509.RevocationList{
		SignatureAlgorithm:        0, //crlCert.SignatureAlgorithm,
		RevokedCertificateEntries: nil,
		Number:                    big.NewInt(1), // CRL number, increment for each new CRL
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().AddDate(1, 0, 0),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, crlCert, key)

	if f, err := os.Create(crlFile); err == nil {
		block := &pem.Block{Type: "X509 CRL", Bytes: crlBytes}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	if f, err := os.Create(keyFile); err == nil {
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	return nil
}

func MethodCaller(ch *client.Client, method ua.CallMethodRequest) *ua.CallMethodResult {
	req := &ua.CallRequest{
		MethodsToCall: []ua.CallMethodRequest{method},
	}

	res, err := ch.Call(context.Background(), req)
	if err != nil {
		fmt.Printf("Error calling method. %s\n", err.Error())
		return nil
	}
	if res == nil || res.Results[0].StatusCode.IsBad() {
		fmt.Printf("Bad result. \n")
		return nil
	}

	return &res.Results[0]
}

func AutomaticSigning(csr []byte) []byte {
	// Read certificate request
	certReq, _ := x509.ParseCertificateRequest(csr)

	// Read root certificate
	rootCertByteAr, err := os.ReadFile("./pki/client.crt")
	if err != nil {
		print(err)
	}
	block, _ := pem.Decode(rootCertByteAr)
	rootCert, _ := x509.ParseCertificate(block.Bytes)

	rootCertKeyByteAr, _ := os.ReadFile("./pki/client.key")
	block, _ = pem.Decode(rootCertKeyByteAr)
	rootCertKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		print(err)
	}

	// Create template for certificate creation, uses properties from the request and root certificate.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		Signature:          rootCert.Signature,
		SignatureAlgorithm: rootCert.SignatureAlgorithm,

		PublicKeyAlgorithm: certReq.PublicKeyAlgorithm,
		PublicKey:          certReq.PublicKey,

		SerialNumber: serialNumber,
		Issuer:       rootCert.Issuer,
		Subject:      certReq.Subject,
		URIs:         certReq.URIs,
		IPAddresses:  certReq.IPAddresses,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment + x509.KeyUsageDataEncipherment + x509.KeyUsageDigitalSignature + x509.KeyUsageContentCommitment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Create certificate from template and root certificate, signed by the RootCA's private key.
	certData, _ := x509.CreateCertificate(rand.Reader, &template, rootCert, certReq.PublicKey, rootCertKey)

	fmt.Println("Created Certificate from CSR, signed by RootCA's Private Key.")

	return certData
}

func CreateSigningRequest(ch *client.Client) []byte {
	method := ua.CallMethodRequest{
		ObjectID: ua.ObjectIDServerConfiguration,
		MethodID: ua.MethodIDServerConfigurationCreateSigningRequest,
		InputArguments: []ua.Variant{
			ua.ObjectIDServerConfigurationCertificateGroupsDefaultApplicationGroup,
			ua.ObjectTypeIDRsaSha256ApplicationCertificateType,
			nil,
			false,
			nil,
		},
	}

	result := MethodCaller(ch, method)

	// Decode output
	resByteString := result.OutputArguments[0].(ua.ByteString)
	resDecoded, _ := base64.StdEncoding.DecodeString(resByteString.String())

	fmt.Printf("Successfully created signing request.\n")

	return resDecoded
}

func UpdateCertificateRequest(ch *client.Client, newCert []byte) {
	method := ua.CallMethodRequest{
		ObjectID: ua.ObjectIDServerConfiguration,
		MethodID: ua.MethodIDServerConfigurationUpdateCertificate,
		InputArguments: []ua.Variant{
			ua.ObjectIDServerConfigurationCertificateGroupsDefaultApplicationGroup,
			ua.ObjectTypeIDRsaSha256ApplicationCertificateType,
			ua.ByteString(newCert),
			nil,
			nil,
			nil,
		},
	}

	MethodCaller(ch, method)

	fmt.Printf("Successfully updated certificate.\n")
}

func ConvertIntToHex32LE(N int) string {
	var s string
	h := fmt.Sprintf("%08x", N)
	for i := 6; i > -2; i = i - 2 {
		s += fmt.Sprintf("%c%c", h[i], h[i+1])
	}
	return s
}

func BuildByteString(certs []string) []byte {
	// Accept an unknown number of certificate paths to construct the UA Write request byte string
	// As long as os.ReadFile() works, the path should be fine
	// Must be adapted to conform to TrustListMasks structure : https://reference.opcfoundation.org/GDS/v104/docs/7.5.8
	var result string

	// Setting up the header
	result += ConvertIntToHex32LE(15)

	// Loop through the certs
	for i := 0; i < len(certs); i++ {
		result += ConvertIntToHex32LE(1)
		fileContents, err := os.ReadFile(certs[i])
		if err != nil {
			fmt.Printf("%s not found, ignoring file.", certs[i])
		}
		result += ConvertIntToHex32LE(len(fileContents)) // The length of the string is also the size in bytes
		result += fmt.Sprintf("%x", fileContents)
		//result += ConvertIntToHex32LE(1 - i) // Does this work for any number of files? Why?
	}

	result += ConvertIntToHex32LE(0)
	result += ConvertIntToHex32LE(0)
	resultByteAr, _ := hex.DecodeString(result)
	return resultByteAr
}

func OpenRequest(ch *client.Client) uint32 {
	method := ua.CallMethodRequest{
		ObjectID: ua.ObjectIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList,
		MethodID: ua.MethodIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpen,
		InputArguments: []ua.Variant{
			// The Open Method shall not support modes other than Read (0x01) and the Write + EraseExisting (0x06).
			byte(6),
		},
	}

	result := MethodCaller(ch, method)

	fmt.Printf("Successfully opened filehandle.\n")

	// Return fileHandle
	return result.OutputArguments[0].(uint32)
}

func WriteRequest(ch *client.Client, fileHandle uint32) {
	// First convert client.crt and client.crl to decoded ders
	certCrt, _ := os.ReadFile("./pki/client.crt")
	pemBlock, _ := pem.Decode(certCrt)
	os.WriteFile("./pki/client_crt.der", pemBlock.Bytes, 0644)
	certCrl, _ := os.ReadFile("./pki/client.crl")
	pemBlock, _ = pem.Decode(certCrl)
	os.WriteFile("./pki/client_crl.der", pemBlock.Bytes, 0644)

	// Then do this:
	magic := BuildByteString([]string{"./pki/client_crt.der", "./pki/client_crl.der"})

	method := ua.CallMethodRequest{
		ObjectID: ua.ObjectIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList,
		MethodID: ua.MethodIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWrite,
		InputArguments: []ua.Variant{
			fileHandle,
			ua.ByteString(magic),
		},
	}

	MethodCaller(ch, method)

	fmt.Printf("Successfully written bytes.\n")
}

func CloseAndUpdateRequest(ch *client.Client, fileHandle uint32) {
	method := ua.CallMethodRequest{
		ObjectID: ua.ObjectIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList,
		MethodID: ua.MethodIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListCloseAndUpdate,
		InputArguments: []ua.Variant{
			fileHandle,
		},
	}

	MethodCaller(ch, method)

	fmt.Printf("Successfully closed filehandle and updated bytes.\n")
}

func ApplyChanges(ch *client.Client) {
	// Connect to PLC, which should be in provisioning mode and have a user with the correct runtime rights
	// Currently not working
	// Certificate validation popup after call in UaExpert
	// https://reference.opcfoundation.org/GDS/v105/docs/7.10.6
	method := ua.CallMethodRequest{
		ObjectID:       ua.ObjectIDServerConfiguration,
		MethodID:       ua.MethodIDServerConfigurationApplyChanges,
		InputArguments: []ua.Variant{},
	}

	MethodCaller(ch, method)

	fmt.Printf("Successfully closed filehandle and updated bytes.\n")
}
