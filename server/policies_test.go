package server_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

// TestDisabledSecurityPolicies starts a server with Basic128Rsa15 and Basic256
// disabled, and checks that they are left out of the endpoints and that a
// channel opened with one anyway is refused. The server on the test port, which
// disables nothing, accepts the same client, so the refusal is the option's.
func TestDisabledSecurityPolicies(t *testing.T) {
	ctx := context.Background()
	const policyPort = 46011
	url := fmt.Sprintf("opc.tcp://%s:%d", host, policyPort)
	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI:  fmt.Sprintf("urn:%s:policyserver", host),
			ProductURI:      "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{Text: "policyserver", Locale: "en"},
			ApplicationType: ua.ApplicationTypeServer,
			DiscoveryURLs:   []string{url},
		},
		"./pki/server.crt", "./pki/server.key", url,
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
		server.WithAuthenticateUserNameIdentityFunc(func(id ua.UserNameIdentity, _ string, _ string) error {
			if id.UserName == "root" && id.Password == "secret" {
				return nil
			}
			return ua.BadUserAccessDenied
		}),
		server.WithDisabledSecurityPolicies(ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.ListenAndServe()
	for i := 0; ; i++ {
		if _, err := client.FindServers(ctx, &ua.FindServersRequest{EndpointURL: url}); err == nil {
			break
		}
		if i > 100 {
			t.Fatal("the server did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}

	res, err := client.GetEndpoints(ctx, &ua.GetEndpointsRequest{EndpointURL: url})
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, e := range res.Endpoints {
		have[strings.TrimPrefix(e.SecurityPolicyURI, "http://opcfoundation.org/UA/SecurityPolicy#")] = true
		for _, tok := range e.UserIdentityTokens {
			if strings.HasSuffix(tok.SecurityPolicyURI, "Basic256") || strings.HasSuffix(tok.SecurityPolicyURI, "Basic128Rsa15") {
				t.Errorf("a user token policy still names %s", tok.SecurityPolicyURI)
			}
		}
	}
	for _, name := range []string{"Basic128Rsa15", "Basic256"} {
		if have[name] {
			t.Errorf("%s is still offered", name)
		}
	}
	for _, name := range []string{"None", "Basic256Sha256", "Aes128_Sha256_RsaOaep", "Aes256_Sha256_RsaPss"} {
		if !have[name] {
			t.Errorf("%s is no longer offered; have %v", name, have)
		}
	}

	dial := func(endpoint, policy string) error {
		ch, err := client.Dial(ctx, endpoint,
			client.WithSecurityPolicyURI(policy, ua.MessageSecurityModeSignAndEncrypt),
			client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),
			client.WithInsecureSkipVerify(),
			client.WithUserNameIdentity("root", "secret"),
		)
		if err == nil {
			ch.Close(ctx)
		}
		return err
	}
	for _, policy := range []string{ua.SecurityPolicyURIBasic128Rsa15, ua.SecurityPolicyURIBasic256} {
		if err := dial(url, policy); err == nil {
			t.Errorf("a channel on %s was opened on the server that disables it", policy)
		}
		if err := dial(endpointURL, policy); err != nil {
			t.Errorf("control: the server that disables nothing refused %s: %v", policy, err)
		}
	}
	if err := dial(url, ua.SecurityPolicyURIBasic256Sha256); err != nil {
		t.Errorf("Basic256Sha256 on the server that disables the others: %v", err)
	}
}
