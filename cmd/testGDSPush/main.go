package main

import (
	"context"
	"fmt"
	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
	"os"
)

func main() {
	err := ensurePKI()
	if err != nil {
		print(err)
	}

	ch := InitClient()
	UpdatePLCCertificate(ch)
	OpenWriteCloseAndUpdate(ch)

	fmt.Printf("Please press 'Apply Changes' in UaExpert to finish provisioning.\n")

	ApplyChanges(ch)

	CloseClient(ch)
}

func ensurePKI() (err error) {
	// check if ./pki already exists
	_, err = os.Stat("./pki")
	// make ./pki if it does not
	if os.IsNotExist(err) {
		err = os.Mkdir("./pki", 0755)
	}
	err = createNewCertificate("client", "./pki/client.crt", "./pki/client.key", "./pki/client.crl")
	return err
}

func InitClient() *client.Client {
	ctx := context.Background()
	ch, err := client.Dial(
		ctx, "opc.tcp://192.168.0.1:4840",
		client.WithUserNameIdentity("root", "Secret.1"), // Must be 8 characters
		client.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
		client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
		client.WithInsecureSkipVerify(),
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return nil
	}
	return ch
}

func UpdatePLCCertificate(ch *client.Client) {
	csr := CreateSigningRequest(ch)

	signed := AutomaticSigning(csr)

	UpdateCertificateRequest(ch, signed)
}

func OpenWriteCloseAndUpdate(ch *client.Client) {
	fileHandle := OpenRequest(ch)

	WriteRequest(ch, fileHandle)

	CloseAndUpdateRequest(ch, fileHandle)
}

func CloseClient(ch *client.Client) {
	err := ch.Close(context.Background())
	if err != nil {
		return
	}
}
