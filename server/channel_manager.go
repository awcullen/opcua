// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"sync"
	"time"
)

// ChannelManager manages the secure channels for a server.
type ChannelManager struct {
	sync.RWMutex
	server       *Server
	channelsByID map[uint32]*serverSecureChannel
}

// NewChannelManager instantiates a new ChannelManager.
func NewChannelManager(server *Server) *ChannelManager {
	m := &ChannelManager{server: server, channelsByID: make(map[uint32]*serverSecureChannel)}
	go func(m *ChannelManager) {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.checkForClosedChannels()
			case <-m.server.closed:
				m.RLock()
				for _, ch := range m.channelsByID {
					ch.Close()
				}
				m.RUnlock()
				return
			}
		}
	}(m)
	return m
}

// Get a secure channel from the server.
func (m *ChannelManager) Get(id uint32) (*serverSecureChannel, bool) {
	m.RLock()
	if ch, ok := m.channelsByID[id]; ok {
		m.RUnlock()
		return ch, ok
	}
	m.RUnlock()
	return nil, false
}

// Add a secure channel to the server.
func (m *ChannelManager) Add(ch *serverSecureChannel) error {
	m.Lock()
	m.channelsByID[ch.channelID] = ch
	m.Unlock()
	return nil
}

// Delete the secure channel from the server.
func (m *ChannelManager) Delete(ch *serverSecureChannel) {
	m.Lock()
	delete(m.channelsByID, ch.channelID)
	m.Unlock()
}

// Len returns the number of secure channel.
func (m *ChannelManager) Len() int {
	m.RLock()
	res := len(m.channelsByID)
	m.RUnlock()
	return res
}

func (m *ChannelManager) checkForClosedChannels() {
	m.Lock()
	for k, ch := range m.channelsByID {
		if ch.closed {
			delete(m.channelsByID, k)
			// log.Printf("Deleted expired channel '%d'.\n", ch.channelId)
		}
	}
	m.Unlock()
}
