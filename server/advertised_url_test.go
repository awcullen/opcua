// Copyright 2021 Converter Systems LLC. All rights reserved.

package server_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

// TestDiscoveryNamesTheHostTheClientUsed starts a server bound to every interface
// (opc.tcp://0.0.0.0:port) and reads FindServers and GetEndpoints off the wire, once
// connecting by IP address and once by host name. No URL in either answer may name the
// unspecified address, which no client can dial: each names the host the client used.
func TestDiscoveryNamesTheHostTheClientUsed(t *testing.T) {
	const port = 46018
	for _, bind := range []string{"0.0.0.0", "[::]"} {
		endpointURL := fmt.Sprintf("opc.tcp://%s:%d", bind, port)
		srv, err := server.New(
			ua.ApplicationDescription{
				ApplicationURI:  fmt.Sprintf("urn:%s:advertised", host),
				ApplicationName: ua.LocalizedText{Text: "advertised"},
				ApplicationType: ua.ApplicationTypeServer,
				DiscoveryURLs:   []string{endpointURL},
			},
			"./pki/server.crt",
			"./pki/server.key",
			endpointURL,
			server.WithSecurityPolicyNone(true),
			server.WithInsecureSkipVerify(),
		)
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan error, 1)
		go func() { served <- srv.ListenAndServe() }()
		time.Sleep(200 * time.Millisecond)

		for _, dialHost := range []string{"127.0.0.1", "localhost"} {
			t.Run(bind+"/"+dialHost, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				dialURL := fmt.Sprintf("opc.tcp://%s:%d", dialHost, port)
				var got []string
				fs, err := client.FindServers(ctx, &ua.FindServersRequest{EndpointURL: dialURL})
				if err != nil {
					t.Fatalf("FindServers: %v", err)
				}
				if len(fs.Servers) == 0 {
					t.Fatal("FindServers returned no server")
				}
				for _, s := range fs.Servers {
					got = append(got, s.DiscoveryURLs...)
				}
				ge, err := client.GetEndpoints(ctx, &ua.GetEndpointsRequest{EndpointURL: dialURL})
				if err != nil {
					t.Fatalf("GetEndpoints: %v", err)
				}
				if len(ge.Endpoints) == 0 {
					t.Fatal("GetEndpoints returned no endpoint")
				}
				for _, ep := range ge.Endpoints {
					got = append(got, ep.EndpointURL)
					got = append(got, ep.Server.DiscoveryURLs...)
				}
				for _, g := range got {
					u, err := url.Parse(g)
					if err != nil {
						t.Fatalf("advertised URL %q: %v", g, err)
					}
					if u.Hostname() != dialHost || u.Port() != fmt.Sprint(port) {
						t.Errorf("advertised URL %q, want host %s port %d", g, dialHost, port)
					}
				}
			})
		}
		srv.Close()
		<-served
	}
}
