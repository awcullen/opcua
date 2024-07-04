package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

func createCACertificate(commonName, organization, certFile, keyFile, crlFile string) error {

	// create a keypair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	// create a certificate.
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subjectKeyHash := sha1.New()
	subjectKeyHash.Write(key.PublicKey.N.Bytes())
	subjectKeyId := subjectKeyHash.Sum(nil)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{organization}},
		SubjectKeyId:          subjectKeyId,
		AuthorityKeyId:        subjectKeyId,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
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
	if f, err := os.Create("./pki/ca.der"); err == nil {
		f.Write(rawcrt)
		f.Close()
	}

	// Also create empty revocation list
	crlCert, err := x509.ParseCertificate(rawcrt)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	crlTemplate := x509.RevocationList{
		Number:     big.NewInt(1), // CRL number, increment for each new CRL
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().AddDate(1, 0, 0),
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &crlTemplate, crlCert, key)
	if err != nil {
		return ua.BadCertificateInvalid
	}

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

func createClientCertificate(appName, certFile, keyFile string) error {

	// create a keypair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	// get local hostname.
	host, _ := os.Hostname()

	// get root certificate
	rootCertByteAr, err := os.ReadFile("./pki/ca.crt")
	if err != nil {
		print(err)
	}
	block, _ := pem.Decode(rootCertByteAr)
	rootCert, _ := x509.ParseCertificate(block.Bytes)

	rootCertKeyByteAr, _ := os.ReadFile("./pki/ca.key")
	block, _ = pem.Decode(rootCertKeyByteAr)
	rootCertKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		print(err)
	}

	// create a client certificate signed by root ca
	applicationURI, _ := url.Parse(fmt.Sprintf("urn:%s:%s", host, appName))
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subjectKeyHash := sha1.New()
	subjectKeyHash.Write(key.PublicKey.N.Bytes())
	subjectKeyId := subjectKeyHash.Sum(nil)
	oidDC := asn1.ObjectIdentifier([]int{0, 9, 2342, 19200300, 100, 1, 25})

	template := x509.Certificate{
		Signature:          rootCert.Signature,
		SignatureAlgorithm: rootCert.SignatureAlgorithm,

		SerialNumber: serialNumber,
		Issuer:       rootCert.Issuer,
		//AuthorityKeyId:        subjectKeyId,
		Subject:               pkix.Name{CommonName: appName, ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidDC, Value: host}}},
		SubjectKeyId:          subjectKeyId,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
		URIs:                  []*url.URL{applicationURI},
	}

	rawcrt, err := x509.CreateCertificate(rand.Reader, &template, rootCert, &key.PublicKey, rootCertKey)
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

func MethodCaller(ch *client.Client, method ua.CallMethodRequest) (*ua.CallMethodResult, error) {
	req := &ua.CallRequest{
		MethodsToCall: []ua.CallMethodRequest{method},
	}

	res, err := ch.Call(context.Background(), req)
	if err != nil {
		return nil, err
	}
	if res.ServiceResult.IsBad() {
		return nil, res.ServiceResult
	}

	return &res.Results[0], nil
}

func CreateCertificateFromRequest(csr []byte) []byte {
	// Read certificate request
	certReq, _ := x509.ParseCertificateRequest(csr)

	// Read root certificate
	rootCertByteAr, err := os.ReadFile("./pki/ca.crt")
	if err != nil {
		print(err)
	}
	block, _ := pem.Decode(rootCertByteAr)
	rootCert, _ := x509.ParseCertificate(block.Bytes)

	rootCertKeyByteAr, _ := os.ReadFile("./pki/ca.key")
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
		DNSNames:     certReq.DNSNames,
		IPAddresses:  certReq.IPAddresses,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:     x509.KeyUsageKeyEncipherment + x509.KeyUsageDataEncipherment + x509.KeyUsageDigitalSignature + x509.KeyUsageContentCommitment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Create certificate from template and root certificate, signed by the RootCA's private key.
	certData, _ := x509.CreateCertificate(rand.Reader, &template, rootCert, certReq.PublicKey, rootCertKey)

	fmt.Println("Created Certificate from CSR, signed by Project CA's Private Key.")

	return certData
}

// see https://reference.opcfoundation.org/GDS/v105/docs/7.10.7
func CreateSigningRequest(ch *client.Client) ([]byte, error) {
	method := ua.CallMethodRequest{
		ObjectID: ua.ObjectIDServerConfiguration,
		MethodID: ua.MethodIDServerConfigurationCreateSigningRequest,
		InputArguments: []ua.Variant{
			ua.ObjectIDServerConfigurationCertificateGroupsDefaultApplicationGroup,
			ua.ObjectTypeIDRsaSha256ApplicationCertificateType,
			"",
			false,
			ua.ByteString(""),
		},
	}

	result, err := MethodCaller(ch, method)
	if err != nil {
		return nil, err
	}
	if result.StatusCode.IsBad() {
		return nil, result.StatusCode
	}
	// Decode output
	resByteString := result.OutputArguments[0].(ua.ByteString)
	resDecoded, _ := base64.StdEncoding.DecodeString(resByteString.String())

	fmt.Printf("Successfully created signing request.\n")

	return resDecoded, nil
}

// see https://reference.opcfoundation.org/GDS/v105/docs/7.10.4
func UpdateCertificate(ch *client.Client, newCert []byte) (bool, error) {
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

	result, err := MethodCaller(ch, method)
	if err != nil {
		return false, err
	}
	if result.StatusCode.IsBad() {
		return false, result.StatusCode
	}

	fmt.Printf("Successfully updated certificate.\n")

	// Return applyChangesRequired
	return result.OutputArguments[0].(bool), nil
}

// see https://reference.opcfoundation.org/Core/Part20/v105/docs/4.2.2
func OpenTrustList(ch *client.Client) (uint32, error) {
	method := ua.CallMethodRequest{
		ObjectID: ua.ObjectIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList,
		MethodID: ua.MethodIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListOpen,
		InputArguments: []ua.Variant{
			// The Open Method shall not support modes other than Read (0x01) and the Write + EraseExisting (0x06).
			byte(6),
		},
	}

	result, err := MethodCaller(ch, method)
	if err != nil {
		return 0, err
	}
	if result.StatusCode.IsBad() {
		return 0, result.StatusCode
	}
	fmt.Printf("Successfully opened filehandle.\n")

	// Return fileHandle
	return result.OutputArguments[0].(uint32), nil
}

// see https://reference.opcfoundation.org/Core/Part20/v105/docs/4.2.5
func WriteTrustList(ch *client.Client, fileHandle uint32) error {
	// clientCrt, _ := os.ReadFile("./pki/client.crt")
	// clientCrtPem, _ := pem.Decode(clientCrt)
	caCrt, _ := os.ReadFile("./pki/ca.crt")
	caCrtPem, _ := pem.Decode(caCrt)
	caCrl, _ := os.ReadFile("./pki/ca.crl")
	caCrlPem, _ := pem.Decode(caCrl)

	list := ua.TrustListDataType{
		SpecifiedLists:      15,
		TrustedCertificates: []ua.ByteString{ua.ByteString(caCrtPem.Bytes)},
		TrustedCrls:         []ua.ByteString{ua.ByteString(caCrlPem.Bytes)},
		IssuerCertificates:  []ua.ByteString{},
		IssuerCrls:          []ua.ByteString{},
	}

	buf := &bytes.Buffer{}
	enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
	err := enc.Encode(list)
	if err != nil {
		return err
	}

	method := ua.CallMethodRequest{
		ObjectID: ua.ObjectIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList,
		MethodID: ua.MethodIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListWrite,
		InputArguments: []ua.Variant{
			fileHandle,
			ua.ByteString(buf.Bytes()),
		},
	}

	result, err := MethodCaller(ch, method)
	if err != nil {
		return err
	}
	if result.StatusCode.IsBad() {
		return result.StatusCode
	}
	fmt.Printf("Successfully written bytes.\n")
	return nil
}

// see https://reference.opcfoundation.org/GDS/v105/docs/7.8.2.3
func CloseAndUpdateTrustList(ch *client.Client, fileHandle uint32) (bool, error) {
	method := ua.CallMethodRequest{
		ObjectID: ua.ObjectIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustList,
		MethodID: ua.MethodIDServerConfigurationCertificateGroupsDefaultApplicationGroupTrustListCloseAndUpdate,
		InputArguments: []ua.Variant{
			fileHandle,
		},
	}

	result, err := MethodCaller(ch, method)
	if err != nil {
		return false, err
	}
	if result.StatusCode.IsBad() {
		return false, result.StatusCode
	}

	fmt.Printf("Successfully closed filehandle and updated trustlist.\n")

	// Return applyChangesRequired
	return result.OutputArguments[0].(bool), nil
}

// see https://reference.opcfoundation.org/GDS/v105/docs/7.10.6
func ApplyChanges(ch *client.Client) error {
	// Connect to PLC, which should be in provisioning mode and have a user with the correct runtime rights
	// Currently not working
	// Certificate validation popup after call in UaExpert
	// https://reference.opcfoundation.org/GDS/v105/docs/7.10.6
	method := ua.CallMethodRequest{
		ObjectID:       ua.ObjectIDServerConfiguration,
		MethodID:       ua.MethodIDServerConfigurationApplyChanges,
		InputArguments: []ua.Variant{},
	}

	result, err := MethodCaller(ch, method)
	if err != nil {
		return err
	}
	if result.StatusCode.IsBad() {
		return result.StatusCode
	}
	fmt.Printf("Successfully applied changes.\n")
	return nil
}

// GetNextNonce gets next random nonce of requested length.
func GetNextNonce(length int) []byte {
	var nonce = make([]byte, length)
	rand.Read(nonce)
	return nonce
}
