// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/awcullen/opcua"
	"github.com/awcullen/opcua/client"
)

// RegistrationManager manages registering the server with the local discovery server.
type RegistrationManager struct {
	sync.RWMutex
	server             *Server
	useRegisterServer2 bool
	wg                 sync.WaitGroup
}

// NewRegistrationManager instantiates a new RegistrationManager.
func NewRegistrationManager(server *Server) *RegistrationManager {
	m := &RegistrationManager{server: server, useRegisterServer2: true}
	if server.registrationURL == "" || server.registrationInterval <= 0.0 {
		return m
	}
	// start registration
	m.wg.Add(1)
	go func(m *RegistrationManager) {
		ticker := time.NewTicker(time.Duration(int64(server.registrationInterval)) * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.updateRegistration()

			case <-m.server.closing:
				m.updateRegistration()
				m.wg.Done()
				return
			}
		}
	}(m)
	return m
}

// Wait blocks until the RegistrationManager completes work.
func (m *RegistrationManager) Wait() {
	m.wg.Wait()
}

func (m *RegistrationManager) updateRegistration() {
	m.Lock()
	defer m.Unlock()
	ad := m.server.localDescription
	registeredServer := opcua.RegisteredServer{
		ServerURI:        ad.ApplicationURI,
		ProductURI:       ad.ProductURI,
		ServerNames:      []opcua.LocalizedText{ad.ApplicationName},
		ServerType:       ad.ApplicationType,
		GatewayServerURI: ad.GatewayServerURI,
		DiscoveryURLs:    ad.DiscoveryURLs,
		IsOnline:         m.server.state == opcua.ServerStateRunning,
	}
	ctx := context.Background()
	if m.useRegisterServer2 {
		discConfig := []interface{}{
			&opcua.MdnsDiscoveryConfiguration{
				MdnsServerName:     ad.ApplicationName.Text,
				ServerCapabilities: []string{"DA"},
			},
		}
		_, err := client.RegisterServer2(ctx, "opc.tcp://127.0.0.1:4840", &opcua.RegisterServer2Request{Server: registeredServer, DiscoveryConfiguration: []opcua.ExtensionObject{discConfig}})
		if err != nil {
			log.Printf("Error registering server (using RegisterServer2) with '%s'. %s\n", m.server.registrationURL, err)
			m.useRegisterServer2 = false
		}
	} else {
		_, err := client.RegisterServer(ctx, "opc.tcp://127.0.0.1:4840", &opcua.RegisterServerRequest{Server: registeredServer})
		if err != nil {
			log.Printf("Error registering server with '%s'. %s\n", m.server.registrationURL, err)
		}
	}
}
