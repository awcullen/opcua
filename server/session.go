package server

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awcullen/opcua/ua"
)

type publishOp struct {
	ch        *serverSecureChannel
	requestId uint32
	req       *ua.PublishRequest
	results   []ua.StatusCode
}

type stateChangeOp struct {
	subscriptionId uint32
	message        ua.NotificationMessage
}

type Session struct {
	sync.RWMutex
	server              *Server
	sessionId           ua.NodeID
	sessionName         string
	authenticationToken ua.NodeID
	timeout             time.Duration
	userIdentity        any
	userRoles           []ua.NodeID
	sessionNonce        ua.ByteString
	lastAccess          time.Time
	publishRequests     chan *publishOp
	stateChanges        chan *stateChangeOp
	channelId           uint32
	browseCPs           map[uint32]struct {
		data []ua.ReferenceDescription
		max  int
	}
	lastBrowseCP                            uint32
	maxBrowseContinuationPoints             int
	historyCPs                              map[uint32]time.Time
	maxHistoryContinuationPoints            int
	clientDescription                       ua.ApplicationDescription
	serverUri                               string
	endpointUrl                             string
	maxResponseMessageSize                  uint32
	localeIds                               []string
	timeCreated                             time.Time
	requestCount                            uint32
	errorCount                              uint32
	unauthorizedRequestCount                uint32
	readCount                               uint32
	readErrorCount                          uint32
	historyReadCount                        uint32
	historyReadErrorCount                   uint32
	writeCount                              uint32
	writeErrorCount                         uint32
	historyUpdateCount                      uint32
	historyUpdateErrorCount                 uint32
	callCount                               uint32
	callErrorCount                          uint32
	createMonitoredItemsCount               uint32
	createMonitoredItemsErrorCount          uint32
	modifyMonitoredItemsCount               uint32
	modifyMonitoredItemsErrorCount          uint32
	setMonitoringModeCount                  uint32
	setMonitoringModeErrorCount             uint32
	setTriggeringCount                      uint32
	setTriggeringErrorCount                 uint32
	deleteMonitoredItemsCount               uint32
	deleteMonitoredItemsErrorCount          uint32
	createSubscriptionCount                 uint32
	createSubscriptionErrorCount            uint32
	modifySubscriptionCount                 uint32
	modifySubscriptionErrorCount            uint32
	setPublishingModeCount                  uint32
	setPublishingModeErrorCount             uint32
	publishCount                            uint32
	publishErrorCount                       uint32
	republishCount                          uint32
	republishErrorCount                     uint32
	transferSubscriptionsCount              uint32
	transferSubscriptionsErrorCount         uint32
	deleteSubscriptionsCount                uint32
	deleteSubscriptionsErrorCount           uint32
	addNodesCount                           uint32
	addNodesErrorCount                      uint32
	addReferencesCount                      uint32
	addReferencesErrorCount                 uint32
	deleteNodesCount                        uint32
	deleteNodesErrorCount                   uint32
	deleteReferencesCount                   uint32
	deleteReferencesErrorCount              uint32
	browseCount                             uint32
	browseErrorCount                        uint32
	browseNextCount                         uint32
	browseNextErrorCount                    uint32
	translateBrowsePathsToNodeIdsCount      uint32
	translateBrowsePathsToNodeIdsErrorCount uint32
	queryFirstCount                         uint32
	queryFirstErrorCount                    uint32
	queryNextCount                          uint32
	queryNextErrorCount                     uint32
	registerNodesCount                      uint32
	registerNodesErrorCount                 uint32
	unregisterNodesCount                    uint32
	unregisterNodesErrorCount               uint32
	clientUserIdOfSession                   string
	authenticationMechanism                 string
	clientUserIdHistory                     []string
}

func NewSession(server *Server, sessionId ua.NodeID, sessionName string, authenticationToken ua.NodeID, sessionNonce ua.ByteString, timeout time.Duration, clientDescription ua.ApplicationDescription, serverUri string, endpointUrl string, maxResponseMessageSize uint32) *Session {
	return &Session{
		server:              server,
		sessionId:           sessionId,
		sessionName:         sessionName,
		authenticationToken: authenticationToken,
		timeout:             timeout,
		sessionNonce:        sessionNonce,
		lastAccess:          time.Now(),
		publishRequests:     make(chan *publishOp, 64),
		stateChanges:        make(chan *stateChangeOp, 64),
		browseCPs: make(map[uint32]struct {
			data []ua.ReferenceDescription
			max  int
		}, 16),
		maxBrowseContinuationPoints:  int(server.ServerCapabilities().MaxBrowseContinuationPoints),
		historyCPs:                   make(map[uint32]time.Time, 16),
		maxHistoryContinuationPoints: int(server.ServerCapabilities().MaxHistoryContinuationPoints),
		clientDescription:            clientDescription,
		serverUri:                    serverUri,
		endpointUrl:                  endpointUrl,
		localeIds:                    []string{"en-US"},
		maxResponseMessageSize:       maxResponseMessageSize,
		timeCreated:                  time.Now(),
		clientUserIdHistory:          []string{},
	}
}

func (s *Session) IsExpired() bool {
	s.RLock()
	defer s.RUnlock()
	return time.Now().After(s.lastAccess.Add(s.timeout))
}

func (s *Session) delete() {
	s.Lock()
	defer s.Unlock()
	s.server = nil
	//s.sessionId = nil  // need to keep to look up diagnostics node
	s.authenticationToken = nil
	s.userIdentity = nil
	s.userRoles = nil
	s.sessionNonce = ua.ByteString("")
	s.publishRequests = nil
	for k := range s.browseCPs {
		delete(s.browseCPs, k)
	}
	s.browseCPs = nil
	for k := range s.historyCPs {
		delete(s.historyCPs, k)
	}
	s.historyCPs = nil
	s.clientUserIdHistory = nil
}

func (s *Session) Server() *Server {
	s.RLock()
	defer s.RUnlock()
	return s.server
}

func (s *Session) SessionId() ua.NodeID {
	s.RLock()
	defer s.RUnlock()
	return s.sessionId
}

func (s *Session) SessionName() string {
	s.RLock()
	defer s.RUnlock()
	return s.sessionName
}

func (s *Session) AuthenticationToken() ua.NodeID {
	s.RLock()
	defer s.RUnlock()
	return s.authenticationToken
}

func (s *Session) Timeout() time.Duration {
	s.RLock()
	defer s.RUnlock()
	return s.timeout
}

func (s *Session) UserIdentity() any {
	s.RLock()
	defer s.RUnlock()
	return s.userIdentity
}

func (s *Session) SetUserIdentity(value any) {
	s.Lock()
	defer s.Unlock()
	s.userIdentity = value
	// update diagnostics
	switch ui := s.userIdentity.(type) {
	case ua.IssuedIdentity:
		s.clientUserIdOfSession = "<issued>"
		s.authenticationMechanism = "Issued"
	case ua.X509Identity:
		s.clientUserIdOfSession = "<certificate>"
		s.authenticationMechanism = "X509"
	case ua.UserNameIdentity:
		s.clientUserIdOfSession = ui.UserName
		s.authenticationMechanism = "UserName"
	default:
		s.clientUserIdOfSession = "<anonymous>"
		s.authenticationMechanism = "Anonymous"
	}
	s.clientUserIdHistory = append(s.clientUserIdHistory, s.clientUserIdOfSession)
}

func (s *Session) UserRoles() []ua.NodeID {
	s.RLock()
	defer s.RUnlock()
	return s.userRoles
}

func (s *Session) SetUserRoles(value []ua.NodeID) {
	s.Lock()
	defer s.Unlock()
	s.userRoles = value
}

func (s *Session) SessionNonce() ua.ByteString {
	s.RLock()
	defer s.RUnlock()
	return s.sessionNonce
}

func (s *Session) SetSessionNonce(value ua.ByteString) {
	s.Lock()
	defer s.Unlock()
	s.sessionNonce = value
}

func (s *Session) LastAccess() time.Time {
	s.RLock()
	defer s.RUnlock()
	return s.lastAccess
}

func (s *Session) SetLastAccess(value time.Time) {
	s.Lock()
	defer s.Unlock()
	s.lastAccess = value
}

func (s *Session) SecureChannelId() uint32 {
	s.RLock()
	defer s.RUnlock()
	return s.channelId
}

func (s *Session) SetSecureChannelId(value uint32) {
	s.Lock()
	defer s.Unlock()
	s.channelId = value
}

func (s *Session) addPublishRequest(ch *serverSecureChannel, requestid uint32, req *ua.PublishRequest, results []ua.StatusCode) error {
	for {
		select {
		case s.publishRequests <- &publishOp{ch, requestid, req, results}:
			return nil
		default:
			op := <-s.publishRequests
			err := op.ch.Write(
				&ua.ServiceFault{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: op.req.RequestHandle,
						ServiceResult: ua.BadTooManyPublishRequests,
					},
				},
				op.requestId,
			)
			if err != nil {
				return err
			}
		}
	}
}

func (s *Session) removePublishRequest() (*serverSecureChannel, uint32, *ua.PublishRequest, []ua.StatusCode, bool, error) {
	for {
		select {
		case op := <-s.publishRequests:
			ch := op.ch
			req := op.req
			rid := op.requestId
			results := op.results
			// check if expired
			if time.Now().After(req.RequestHeader.Timestamp.Add(time.Duration(req.RequestHeader.TimeoutHint) * time.Millisecond)) {
				err := ch.Write(
					&ua.ServiceFault{
						ResponseHeader: ua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHandle,
							ServiceResult: ua.BadTimeout,
						},
					},
					rid,
				)
				if err != nil {
					return nil, 0, nil, nil, false, err
				}
				continue
			}
			return ch, rid, req, results, true, nil
		default:
			return nil, 0, nil, nil, false, nil
		}
	}
}

func (s *Session) addBrowseContinuationPoint(data []ua.ReferenceDescription, max int) ([]byte, error) {
	s.Lock()
	defer s.Unlock()
	if s.maxBrowseContinuationPoints > 0 && len(s.browseCPs) >= s.maxBrowseContinuationPoints {
		return nil, ua.BadNoContinuationPoints
	}
	id := atomic.AddUint32(&s.lastBrowseCP, 1)
	s.browseCPs[id] = struct {
		data []ua.ReferenceDescription
		max  int
	}{data, max}
	cp := make([]byte, 4)
	binary.LittleEndian.PutUint32(cp, id)
	return cp, nil
}

func (s *Session) removeBrowseContinuationPoint(cp []byte) ([]ua.ReferenceDescription, int, bool) {
	if cp == nil {
		return nil, 0, false
	}
	s.Lock()
	defer s.Unlock()
	id := binary.LittleEndian.Uint32(cp)
	x, ok := s.browseCPs[id]
	if ok {
		delete(s.browseCPs, id)
	}
	if ok {
		return x.data, x.max, ok
	}
	return nil, 0, false
}
