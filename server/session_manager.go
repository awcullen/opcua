package server

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/awcullen/opcua/ua"
	"github.com/google/uuid"
)

// SessionManager manages the sessions for a server.
type SessionManager struct {
	sync.RWMutex
	server          *Server
	sessionsByToken map[ua.NodeID]*Session
}

// NewSessionManager instantiates a new SessionManager.
func NewSessionManager(server *Server) *SessionManager {
	m := &SessionManager{server: server, sessionsByToken: make(map[ua.NodeID]*Session)}
	go func(m *SessionManager) {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.checkForExpiredSessions()
			case <-m.server.closing:
				return
			}
		}
	}(m)
	return m
}

// Get a session from the server by authenticationToken.
func (m *SessionManager) Get(authenticationToken ua.NodeID) (*Session, bool) {
	m.RLock()
	defer m.RUnlock()
	s, ok := m.sessionsByToken[authenticationToken]
	if !ok {
		return nil, false
	}
	s.SetLastAccess(time.Now())
	return s, ok
}

// Add a session to the server.
func (m *SessionManager) Add(s *Session) error {
	m.Lock()
	defer m.Unlock()
	if maxSessionCount := m.server.MaxSessionCount(); maxSessionCount > 0 && len(m.sessionsByToken) >= int(maxSessionCount) {
		return ua.BadTooManySessions
	}
	m.sessionsByToken[s.authenticationToken] = s
	if m.server.serverDiagnostics {
		m.addDiagnosticsNode(s)
		m.server.serverDiagnosticsSummary.CumulatedSessionCount++
		m.server.serverDiagnosticsSummary.CurrentSessionCount = uint32(len(m.sessionsByToken))
	}
	return nil
}

// Delete the session from the server.
func (m *SessionManager) Delete(s *Session) {
	m.Lock()
	defer m.Unlock()
	delete(m.sessionsByToken, s.authenticationToken)
	if m.server.serverDiagnostics {
		m.removeDiagnosticsNode(s)
		m.server.serverDiagnosticsSummary.CurrentSessionCount = uint32(len(m.sessionsByToken))
	}
	s.delete()
}

// Len returns the number of sessions.
func (m *SessionManager) Len() int {
	m.RLock()
	defer m.RUnlock()
	return len(m.sessionsByToken)
}

func (m *SessionManager) checkForExpiredSessions() {
	m.Lock()
	defer m.Unlock()
	for k, s := range m.sessionsByToken {
		if s.IsExpired() {
			delete(m.sessionsByToken, k)
			if m.server.serverDiagnostics {
				m.server.Lock()
				m.server.serverDiagnosticsSummary.SessionTimeoutCount++
				m.server.serverDiagnosticsSummary.CurrentSessionCount = uint32(len(m.sessionsByToken))
				m.server.Unlock()
			}
			s.delete()
		}
	}
}

func (m *SessionManager) addDiagnosticsNode(s *Session) {
	srv := m.server
	nm := srv.NamespaceManager()
	nodes := []Node{}
	sessionDiagnosticsObject := NewObjectNode(
		s.sessionId,
		ua.NewQualifiedName(1, s.sessionName),
		ua.NewLocalizedText(s.sessionName, ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.ObjectTypeIDSessionDiagnosticsObjectType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(ua.ObjectIDServerServerDiagnosticsSessionsDiagnosticsSummary)),
		},
		byte(0),
	)
	nodes = append(nodes, sessionDiagnosticsObject)
	sessionDiagnosticsVariable := NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SessionDiagnostics"),
		ua.NewLocalizedText("SessionDiagnostics", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDSessionDiagnosticsVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsObject.NodeID())),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(ua.VariableIDServerServerDiagnosticsSessionsDiagnosticsSummarySessionDiagnosticsArray)),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDSessionDiagnosticsDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	sessionDiagnosticsVariable.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		subCount := 0
		itemCount := 0
		subs := srv.subscriptionManager.GetBySession(s)
		subCount = len(subs)
		for _, sub := range subs {
			itemCount += len(sub.items)
		}
		return ua.NewDataValue(ua.SessionDiagnosticsDataType{
			SessionID:                          s.sessionId,
			SessionName:                        s.sessionName,
			ClientDescription:                  s.clientDescription,
			ServerURI:                          s.serverUri,
			EndpointURL:                        s.endpointUrl,
			LocaleIDs:                          s.localeIds,
			ActualSessionTimeout:               float64(s.timeout.Nanoseconds() / 1000000),
			MaxResponseMessageSize:             s.maxResponseMessageSize,
			ClientConnectionTime:               s.timeCreated,
			ClientLastContactTime:              s.lastAccess,
			CurrentSubscriptionsCount:          uint32(subCount),
			CurrentMonitoredItemsCount:         uint32(itemCount),
			CurrentPublishRequestsInQueue:      uint32(len(s.publishRequests)),
			TotalRequestCount:                  ua.ServiceCounterDataType{TotalCount: s.requestCount, ErrorCount: s.errorCount},
			UnauthorizedRequestCount:           s.unauthorizedRequestCount,
			ReadCount:                          ua.ServiceCounterDataType{TotalCount: s.readCount, ErrorCount: s.readErrorCount},
			HistoryReadCount:                   ua.ServiceCounterDataType{TotalCount: s.historyReadCount, ErrorCount: s.historyReadErrorCount},
			WriteCount:                         ua.ServiceCounterDataType{TotalCount: s.writeCount, ErrorCount: s.writeErrorCount},
			HistoryUpdateCount:                 ua.ServiceCounterDataType{TotalCount: s.historyUpdateCount, ErrorCount: s.historyUpdateErrorCount},
			CallCount:                          ua.ServiceCounterDataType{TotalCount: s.callCount, ErrorCount: s.callErrorCount},
			CreateMonitoredItemsCount:          ua.ServiceCounterDataType{TotalCount: s.createMonitoredItemsCount, ErrorCount: s.createMonitoredItemsErrorCount},
			ModifyMonitoredItemsCount:          ua.ServiceCounterDataType{TotalCount: s.modifyMonitoredItemsCount, ErrorCount: s.modifyMonitoredItemsErrorCount},
			SetMonitoringModeCount:             ua.ServiceCounterDataType{TotalCount: s.setMonitoringModeCount, ErrorCount: s.setMonitoringModeErrorCount},
			SetTriggeringCount:                 ua.ServiceCounterDataType{TotalCount: s.setTriggeringCount, ErrorCount: s.setTriggeringErrorCount},
			DeleteMonitoredItemsCount:          ua.ServiceCounterDataType{TotalCount: s.deleteMonitoredItemsCount, ErrorCount: s.deleteMonitoredItemsErrorCount},
			CreateSubscriptionCount:            ua.ServiceCounterDataType{TotalCount: s.createSubscriptionCount, ErrorCount: s.createSubscriptionErrorCount},
			ModifySubscriptionCount:            ua.ServiceCounterDataType{TotalCount: s.modifySubscriptionCount, ErrorCount: s.modifySubscriptionErrorCount},
			SetPublishingModeCount:             ua.ServiceCounterDataType{TotalCount: s.setPublishingModeCount, ErrorCount: s.setPublishingModeErrorCount},
			PublishCount:                       ua.ServiceCounterDataType{TotalCount: s.publishCount, ErrorCount: s.publishErrorCount},
			RepublishCount:                     ua.ServiceCounterDataType{TotalCount: s.republishCount, ErrorCount: s.republishErrorCount},
			TransferSubscriptionsCount:         ua.ServiceCounterDataType{TotalCount: s.transferSubscriptionsCount, ErrorCount: s.transferSubscriptionsErrorCount},
			DeleteSubscriptionsCount:           ua.ServiceCounterDataType{TotalCount: s.deleteSubscriptionsCount, ErrorCount: s.deleteSubscriptionsErrorCount},
			AddNodesCount:                      ua.ServiceCounterDataType{TotalCount: s.addNodesCount, ErrorCount: s.addNodesErrorCount},
			AddReferencesCount:                 ua.ServiceCounterDataType{TotalCount: s.addReferencesCount, ErrorCount: s.addReferencesErrorCount},
			DeleteNodesCount:                   ua.ServiceCounterDataType{TotalCount: s.deleteNodesCount, ErrorCount: s.deleteNodesErrorCount},
			DeleteReferencesCount:              ua.ServiceCounterDataType{TotalCount: s.deleteReferencesCount, ErrorCount: s.deleteReferencesErrorCount},
			BrowseCount:                        ua.ServiceCounterDataType{TotalCount: s.browseCount, ErrorCount: s.browseErrorCount},
			BrowseNextCount:                    ua.ServiceCounterDataType{TotalCount: s.browseNextCount, ErrorCount: s.browseNextErrorCount},
			TranslateBrowsePathsToNodeIDsCount: ua.ServiceCounterDataType{TotalCount: s.translateBrowsePathsToNodeIdsCount, ErrorCount: s.translateBrowsePathsToNodeIdsErrorCount},
			QueryFirstCount:                    ua.ServiceCounterDataType{TotalCount: s.queryFirstCount, ErrorCount: s.queryFirstErrorCount},
			QueryNextCount:                     ua.ServiceCounterDataType{TotalCount: s.queryNextCount, ErrorCount: s.queryNextErrorCount},
			RegisterNodesCount:                 ua.ServiceCounterDataType{TotalCount: s.registerNodesCount, ErrorCount: s.registerNodesErrorCount},
			UnregisterNodesCount:               ua.ServiceCounterDataType{TotalCount: s.unregisterNodesCount, ErrorCount: s.unregisterNodesErrorCount},
		}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, sessionDiagnosticsVariable)
	n := NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SessionId"),
		ua.NewLocalizedText("SessionId", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDNodeID,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.sessionId, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SessionName"),
		ua.NewLocalizedText("SessionName", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.sessionName, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ClientDescription"),
		ua.NewLocalizedText("ClientDescription", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.clientDescription, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ServerUri"),
		ua.NewLocalizedText("ServerUri", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.serverUri, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "EndpointUrl"),
		ua.NewLocalizedText("EndpointUrl", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.endpointUrl, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "LocaleIds"),
		ua.NewLocalizedText("LocaleIds", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDString,
		ua.ValueRankOneDimension,
		[]uint32{0},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.localeIds, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ActualSessionTimeout"),
		ua.NewLocalizedText("ActualSessionTimeout", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDDouble,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(float64(s.timeout.Nanoseconds()/1000000), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "MaxResponseMessageSize"),
		ua.NewLocalizedText("MaxResponseMessageSize", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDUInt32,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.maxResponseMessageSize, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ClientConnectionTime"),
		ua.NewLocalizedText("ClientConnectionTime", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDDateTime,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.timeCreated, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ClientLastContactTime"),
		ua.NewLocalizedText("ClientLastContactTime", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDDateTime,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.lastAccess, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "CurrentSubscriptionsCount"),
		ua.NewLocalizedText("CurrentSubscriptionsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDUInt32,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(uint32(len(srv.subscriptionManager.GetBySession(s))), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "CurrentMonitoredItemsCount"),
		ua.NewLocalizedText("CurrentMonitoredItemsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDUInt32,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		itemCount := 0
		subs := srv.subscriptionManager.GetBySession(s)
		for _, sub := range subs {
			itemCount += len(sub.items)
		}
		return ua.NewDataValue(uint32(itemCount), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "CurrentPublishRequestsInQueue"),
		ua.NewLocalizedText("CurrentPublishRequestsInQueue", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDUInt32,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(uint32(len(s.publishRequests)), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "TotalRequestCount"),
		ua.NewLocalizedText("TotalRequestCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.requestCount, ErrorCount: s.errorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "UnauthorizedRequestCount"),
		ua.NewLocalizedText("UnauthorizedRequestCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDUInt32,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.unauthorizedRequestCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ReadCount"),
		ua.NewLocalizedText("ReadCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.readCount, ErrorCount: s.readErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "HistoryReadCount"),
		ua.NewLocalizedText("HistoryReadCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.historyReadCount, ErrorCount: s.historyReadErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "WriteCount"),
		ua.NewLocalizedText("WriteCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.writeCount, ErrorCount: s.writeErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "HistoryUpdateCount"),
		ua.NewLocalizedText("HistoryUpdateCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.historyUpdateCount, ErrorCount: s.historyUpdateErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "CallCount"),
		ua.NewLocalizedText("CallCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.callCount, ErrorCount: s.callErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "CreateMonitoredItemsCount"),
		ua.NewLocalizedText("CreateMonitoredItemsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.createMonitoredItemsCount, ErrorCount: s.createMonitoredItemsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ModifyMonitoredItemsCount"),
		ua.NewLocalizedText("ModifyMonitoredItemsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.modifyMonitoredItemsCount, ErrorCount: s.modifyMonitoredItemsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SetMonitoringModeCount"),
		ua.NewLocalizedText("SetMonitoringModeCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.setMonitoringModeCount, ErrorCount: s.setMonitoringModeErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SetTriggeringCount"),
		ua.NewLocalizedText("SetTriggeringCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.setTriggeringCount, ErrorCount: s.setTriggeringErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "DeleteMonitoredItemsCount"),
		ua.NewLocalizedText("DeleteMonitoredItemsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.deleteMonitoredItemsCount, ErrorCount: s.deleteMonitoredItemsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "CreateSubscriptionCount"),
		ua.NewLocalizedText("CreateSubscriptionCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.createSubscriptionCount, ErrorCount: s.createSubscriptionErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ModifySubscriptionCount"),
		ua.NewLocalizedText("ModifySubscriptionCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.modifySubscriptionCount, ErrorCount: s.modifySubscriptionErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SetPublishingModeCount"),
		ua.NewLocalizedText("SetPublishingModeCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.setPublishingModeCount, ErrorCount: s.setPublishingModeErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "PublishCount"),
		ua.NewLocalizedText("PublishCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.publishCount, ErrorCount: s.publishErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "RepublishCount"),
		ua.NewLocalizedText("RepublishCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.republishCount, ErrorCount: s.republishErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "TransferSubscriptionsCount"),
		ua.NewLocalizedText("TransferSubscriptionsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.transferSubscriptionsCount, ErrorCount: s.transferSubscriptionsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "DeleteSubscriptionsCount"),
		ua.NewLocalizedText("DeleteSubscriptionsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.deleteSubscriptionsCount, ErrorCount: s.deleteSubscriptionsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "AddNodesCount"),
		ua.NewLocalizedText("AddNodesCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.addNodesCount, ErrorCount: s.addNodesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "AddReferencesCount"),
		ua.NewLocalizedText("AddReferencesCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.addReferencesCount, ErrorCount: s.addReferencesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "DeleteNodesCount"),
		ua.NewLocalizedText("DeleteNodesCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.deleteNodesCount, ErrorCount: s.deleteNodesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "DeleteReferencesCount"),
		ua.NewLocalizedText("DeleteReferencesCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.deleteReferencesCount, ErrorCount: s.deleteReferencesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "BrowseCount"),
		ua.NewLocalizedText("BrowseCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.browseCount, ErrorCount: s.browseErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "BrowseNextCount"),
		ua.NewLocalizedText("BrowseNextCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.browseNextCount, ErrorCount: s.browseNextErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "TranslateBrowsePathsToNodeIdsCount"),
		ua.NewLocalizedText("TranslateBrowsePathsToNodeIdsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.translateBrowsePathsToNodeIdsCount, ErrorCount: s.translateBrowsePathsToNodeIdsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "QueryFirstCount"),
		ua.NewLocalizedText("QueryFirstCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.queryFirstCount, ErrorCount: s.queryFirstErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "QueryNextCount"),
		ua.NewLocalizedText("QueryNextCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.queryNextCount, ErrorCount: s.queryNextErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "RegisterNodesCount"),
		ua.NewLocalizedText("RegisterNodesCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.registerNodesCount, ErrorCount: s.registerNodesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "UnregisterNodesCount"),
		ua.NewLocalizedText("UnregisterNodesCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBaseDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(ua.ServiceCounterDataType{TotalCount: s.unregisterNodesCount, ErrorCount: s.unregisterNodesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)

	// SessionSecurityDiagnostics
	sessionSecurityDiagnosticsVariable := NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SessionSecurityDiagnostics"),
		ua.NewLocalizedText("SessionSecurityDiagnostics", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDSessionSecurityDiagnosticsType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsObject.NodeID())),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(ua.VariableIDServerServerDiagnosticsSessionsDiagnosticsSummarySessionSecurityDiagnosticsArray)),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDSessionSecurityDiagnosticsDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	sessionSecurityDiagnosticsVariable.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == ua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			return ua.NewDataValue(nil, ua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return ua.NewDataValue(ua.SessionSecurityDiagnosticsDataType{
			SessionID:               s.sessionId,
			ClientUserIDOfSession:   s.clientUserIdOfSession,
			ClientUserIDHistory:     s.clientUserIdHistory,
			AuthenticationMechanism: s.authenticationMechanism,
			Encoding:                "UA Binary",
			TransportProtocol:       ua.TransportProfileURIUaTcpTransport,
			SecurityMode:            ch.SecurityMode(),
			SecurityPolicyURI:       ch.SecurityPolicyURI(),
			ClientCertificate:       ua.ByteString(ch.RemoteCertificate()),
		}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, sessionSecurityDiagnosticsVariable)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SessionId"),
		ua.NewLocalizedText("SessionId", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDNodeID,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == ua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			return ua.NewDataValue(nil, ua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return ua.NewDataValue(s.sessionId, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ClientUserIdOfSession"),
		ua.NewLocalizedText("ClientUserIdOfSession", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == ua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			return ua.NewDataValue(nil, ua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return ua.NewDataValue(s.clientUserIdOfSession, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ClientUserIdHistory"),
		ua.NewLocalizedText("ClientUserIdHistory", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDString,
		ua.ValueRankOneDimension,
		[]uint32{0},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == ua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			return ua.NewDataValue(nil, ua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return ua.NewDataValue(s.clientUserIdHistory, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "AuthenticationMechanism"),
		ua.NewLocalizedText("AuthenticationMechanism", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == ua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			return ua.NewDataValue(nil, ua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return ua.NewDataValue(s.authenticationMechanism, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "Encoding"),
		ua.NewLocalizedText("Encoding", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == ua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			return ua.NewDataValue(nil, ua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return ua.NewDataValue("UA Binary", 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "TransportProtocol"),
		ua.NewLocalizedText("TransportProtocol", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == ua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			return ua.NewDataValue(nil, ua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return ua.NewDataValue(ua.TransportProfileURIUaTcpTransport, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SecurityMode"),
		ua.NewLocalizedText("SecurityMode", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDMessageSecurityMode,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == ua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			return ua.NewDataValue(nil, ua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return ua.NewDataValue(int32(ch.SecurityMode()), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SecurityPolicyURI"),
		ua.NewLocalizedText("SecurityPolicyURI", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == ua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			return ua.NewDataValue(nil, ua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return ua.NewDataValue(ch.SecurityPolicyURI(), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ClientCertificate"),
		ua.NewLocalizedText("ClientCertificate", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDByteString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == ua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return ua.NewDataValue(nil, ua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != ua.MessageSecurityModeSignAndEncrypt {
			return ua.NewDataValue(nil, ua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return ua.NewDataValue(ua.ByteString(ch.RemoteCertificate()), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)

	// SubscriptionDiagnostics
	subscriptionDiagnosticsArrayVariable := NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SubscriptionDiagnosticsArray"),
		ua.NewLocalizedText("SubscriptionDiagnosticsArray", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDSubscriptionDiagnosticsArrayType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(sessionDiagnosticsObject.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDSubscriptionDiagnosticsDataType,
		ua.ValueRankOneDimension,
		[]uint32{0},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	subscriptionDiagnosticsArrayVariable.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue([]ua.ExtensionObject{}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, subscriptionDiagnosticsArrayVariable)

	err := nm.AddNodes(nodes)
	if err != nil {
		log.Printf("Error adding session diagnostics objects.\n")
	}

}

func (m *SessionManager) removeDiagnosticsNode(s *Session) {
	if n, ok := m.server.NamespaceManager().FindNode(s.SessionId()); ok {
		m.server.NamespaceManager().DeleteNode(n, true)
	}
}
