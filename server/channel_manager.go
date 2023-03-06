// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"log"
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
				m.closeChannels()
				return
			}
		}
	}(m)
	return m
}

// Get a secure channel from the server.
func (m *ChannelManager) Get(id uint32) (*serverSecureChannel, bool) {
	m.RLock()
	defer m.RUnlock()
	if ch, ok := m.channelsByID[id]; ok {
		return ch, ok
	}
	return nil, false
}

// Add a secure channel to the server.
func (m *ChannelManager) Add(ch *serverSecureChannel) error {
	m.Lock()
	defer m.Unlock()
	m.channelsByID[ch.channelID] = ch
	return nil
}

// Delete the secure channel from the server.
func (m *ChannelManager) Delete(ch *serverSecureChannel) {
	m.Lock()
	defer m.Unlock()
	delete(m.channelsByID, ch.channelID)
}

// Len returns the number of secure channel.
func (m *ChannelManager) Len() int {
	m.RLock()
	defer m.RUnlock()
	res := len(m.channelsByID)
	return res
}

func (m *ChannelManager) checkForClosedChannels() {
	m.Lock()
	defer m.Unlock()
	for k, ch := range m.channelsByID {
		if ch.closed {
			delete(m.channelsByID, k)
			log.Printf("Deleted expired channel '%d'. %d channel(s) open.\n", ch.channelID, len(m.channelsByID))
		}
	}
}

func (m *ChannelManager) closeChannels() {
	m.RLock()
	defer m.RUnlock()
	for _, ch := range m.channelsByID {
		ch.Close()
	}
}
