package main

import (
	"context"
	"fmt"
	"os"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

func main() {
	err := ensurePKI()
	if err != nil {
		print(err)
	}

	ch := InitClient()
	if ch == nil {
		fmt.Printf("Error initClient.\n")
		return
	}

	err = UpdatePLCCertificate(ch)
	if err != nil {
		print(err)
		CloseClient(ch)
		return
	}

	err = UpdateTrustList(ch)
	if err != nil {
		print(err)
		CloseClient(ch)
		return
	}

	CloseClient(ch)
}

func ensurePKI() (err error) {
	// check if ./pki already exists
	_, err = os.Stat("./pki")
	// make ./pki if it does not
	if os.IsNotExist(err) {
		err = os.Mkdir("./pki", 0755)
		if err != nil {
			return err
		}
		err = createCACertificate("Project CA", "Project Org", "./pki/ca.crt", "./pki/ca.key", "./pki/ca.crl")
		if err != nil {
			return err
		}
		err = createClientCertificate("client", "./pki/client.crt", "./pki/client.key")
		if err != nil {
			return err
		}
	}
	return nil
}

func InitClient() *client.Client {
	ctx := context.Background()
	ch, err := client.Dial(
		ctx, "opc.tcp://andrew-x1:48010",
		client.WithUserNameIdentity("root", "secret"),
		client.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt),
		client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
		client.WithTrustedCertificatesPaths("./pki/ca.crt", "./pki/ca.crl"),
		client.WithRejectedCertificatesPath("./pki/rejected"),
	)
	if err != nil {
		fmt.Printf("Error opening client connection. %s\n", err.Error())
		return nil
	}
	return ch
}

func UpdatePLCCertificate(ch *client.Client) error {
	csr, err := CreateSigningRequest(ch)
	if err != nil {
		fmt.Printf("Error CreateSigningRequest. %s\n", err.Error())
		return err
	}
	signed := CreateCertificateFromRequest(csr)

	// flag is true if ApplyChanges required
	flag, err := UpdateCertificate(ch, signed)
	if err != nil {
		fmt.Printf("Error UpdateCertificate. %s\n", err.Error())
		return err
	}
	if flag {
		err = ApplyChanges(ch)
		if err != nil {
			print(err)
		}
	} else {
		fmt.Printf("ApplyChanges not required.\n")
	}
	return nil
}

func UpdateTrustList(ch *client.Client) error {
	fileHandle, err := OpenTrustList(ch)
	if err != nil {
		fmt.Printf("Error OpenTrustList. %s\n", err.Error())
		return err
	}

	err = WriteTrustList(ch, fileHandle)
	if err != nil {
		fmt.Printf("Error WriteTrustList. %s\n", err.Error())
		return err
	}
	// flag is true if ApplyChanges required
	flag, err := CloseAndUpdateTrustList(ch, fileHandle)
	if err != nil {
		fmt.Printf("Error CloseAndUpdateTrustList. %s\n", err.Error())
		return err
	}
	if flag {
		err = ApplyChanges(ch)
		if err != nil {
			print(err)
		}
	} else {
		fmt.Printf("ApplyChanges not required.\n")
	}
	return nil
}

func CloseClient(ch *client.Client) {
	err := ch.Close(context.Background())
	if err != nil {
		return
	}
}
