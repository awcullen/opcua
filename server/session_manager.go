package server

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/awcullen/opcua"
	"github.com/google/uuid"
)

// SessionManager manages the sessions for a server.
type SessionManager struct {
	sync.RWMutex
	server          *Server
	sessionsByToken map[opcua.NodeID]*Session
}

// NewSessionManager instantiates a new SessionManager.
func NewSessionManager(server *Server) *SessionManager {
	m := &SessionManager{server: server, sessionsByToken: make(map[opcua.NodeID]*Session)}
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
func (m *SessionManager) Get(authenticationToken opcua.NodeID) (*Session, bool) {
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
		return opcua.BadTooManySessions
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
		opcua.NewQualifiedName(1, s.sessionName),
		opcua.NewLocalizedText(s.sessionName, ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.ObjectTypeIDSessionDiagnosticsObjectType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(opcua.ObjectIDServerServerDiagnosticsSessionsDiagnosticsSummary)),
		},
		byte(0),
	)
	nodes = append(nodes, sessionDiagnosticsObject)
	sessionDiagnosticsVariable := NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SessionDiagnostics"),
		opcua.NewLocalizedText("SessionDiagnostics", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDSessionDiagnosticsVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsObject.NodeID())),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(opcua.VariableIDServerServerDiagnosticsSessionsDiagnosticsSummarySessionDiagnosticsArray)),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDSessionDiagnosticsDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	sessionDiagnosticsVariable.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		subCount := 0
		itemCount := 0
		subs := srv.subscriptionManager.GetBySession(s)
		subCount = len(subs)
		for _, sub := range subs {
			itemCount += len(sub.items)
		}
		return opcua.NewDataValue(opcua.SessionDiagnosticsDataType{
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
			TotalRequestCount:                  opcua.ServiceCounterDataType{TotalCount: s.requestCount, ErrorCount: s.errorCount},
			UnauthorizedRequestCount:           s.unauthorizedRequestCount,
			ReadCount:                          opcua.ServiceCounterDataType{TotalCount: s.readCount, ErrorCount: s.readErrorCount},
			HistoryReadCount:                   opcua.ServiceCounterDataType{TotalCount: s.historyReadCount, ErrorCount: s.historyReadErrorCount},
			WriteCount:                         opcua.ServiceCounterDataType{TotalCount: s.writeCount, ErrorCount: s.writeErrorCount},
			HistoryUpdateCount:                 opcua.ServiceCounterDataType{TotalCount: s.historyUpdateCount, ErrorCount: s.historyUpdateErrorCount},
			CallCount:                          opcua.ServiceCounterDataType{TotalCount: s.callCount, ErrorCount: s.callErrorCount},
			CreateMonitoredItemsCount:          opcua.ServiceCounterDataType{TotalCount: s.createMonitoredItemsCount, ErrorCount: s.createMonitoredItemsErrorCount},
			ModifyMonitoredItemsCount:          opcua.ServiceCounterDataType{TotalCount: s.modifyMonitoredItemsCount, ErrorCount: s.modifyMonitoredItemsErrorCount},
			SetMonitoringModeCount:             opcua.ServiceCounterDataType{TotalCount: s.setMonitoringModeCount, ErrorCount: s.setMonitoringModeErrorCount},
			SetTriggeringCount:                 opcua.ServiceCounterDataType{TotalCount: s.setTriggeringCount, ErrorCount: s.setTriggeringErrorCount},
			DeleteMonitoredItemsCount:          opcua.ServiceCounterDataType{TotalCount: s.deleteMonitoredItemsCount, ErrorCount: s.deleteMonitoredItemsErrorCount},
			CreateSubscriptionCount:            opcua.ServiceCounterDataType{TotalCount: s.createSubscriptionCount, ErrorCount: s.createSubscriptionErrorCount},
			ModifySubscriptionCount:            opcua.ServiceCounterDataType{TotalCount: s.modifySubscriptionCount, ErrorCount: s.modifySubscriptionErrorCount},
			SetPublishingModeCount:             opcua.ServiceCounterDataType{TotalCount: s.setPublishingModeCount, ErrorCount: s.setPublishingModeErrorCount},
			PublishCount:                       opcua.ServiceCounterDataType{TotalCount: s.publishCount, ErrorCount: s.publishErrorCount},
			RepublishCount:                     opcua.ServiceCounterDataType{TotalCount: s.republishCount, ErrorCount: s.republishErrorCount},
			TransferSubscriptionsCount:         opcua.ServiceCounterDataType{TotalCount: s.transferSubscriptionsCount, ErrorCount: s.transferSubscriptionsErrorCount},
			DeleteSubscriptionsCount:           opcua.ServiceCounterDataType{TotalCount: s.deleteSubscriptionsCount, ErrorCount: s.deleteSubscriptionsErrorCount},
			AddNodesCount:                      opcua.ServiceCounterDataType{TotalCount: s.addNodesCount, ErrorCount: s.addNodesErrorCount},
			AddReferencesCount:                 opcua.ServiceCounterDataType{TotalCount: s.addReferencesCount, ErrorCount: s.addReferencesErrorCount},
			DeleteNodesCount:                   opcua.ServiceCounterDataType{TotalCount: s.deleteNodesCount, ErrorCount: s.deleteNodesErrorCount},
			DeleteReferencesCount:              opcua.ServiceCounterDataType{TotalCount: s.deleteReferencesCount, ErrorCount: s.deleteReferencesErrorCount},
			BrowseCount:                        opcua.ServiceCounterDataType{TotalCount: s.browseCount, ErrorCount: s.browseErrorCount},
			BrowseNextCount:                    opcua.ServiceCounterDataType{TotalCount: s.browseNextCount, ErrorCount: s.browseNextErrorCount},
			TranslateBrowsePathsToNodeIDsCount: opcua.ServiceCounterDataType{TotalCount: s.translateBrowsePathsToNodeIdsCount, ErrorCount: s.translateBrowsePathsToNodeIdsErrorCount},
			QueryFirstCount:                    opcua.ServiceCounterDataType{TotalCount: s.queryFirstCount, ErrorCount: s.queryFirstErrorCount},
			QueryNextCount:                     opcua.ServiceCounterDataType{TotalCount: s.queryNextCount, ErrorCount: s.queryNextErrorCount},
			RegisterNodesCount:                 opcua.ServiceCounterDataType{TotalCount: s.registerNodesCount, ErrorCount: s.registerNodesErrorCount},
			UnregisterNodesCount:               opcua.ServiceCounterDataType{TotalCount: s.unregisterNodesCount, ErrorCount: s.unregisterNodesErrorCount},
		}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, sessionDiagnosticsVariable)
	n := NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SessionId"),
		opcua.NewLocalizedText("SessionId", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDNodeID,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.sessionId, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SessionName"),
		opcua.NewLocalizedText("SessionName", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDString,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.sessionName, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ClientDescription"),
		opcua.NewLocalizedText("ClientDescription", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.clientDescription, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ServerUri"),
		opcua.NewLocalizedText("ServerUri", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDString,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.serverUri, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "EndpointUrl"),
		opcua.NewLocalizedText("EndpointUrl", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDString,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.endpointUrl, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "LocaleIds"),
		opcua.NewLocalizedText("LocaleIds", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDString,
		opcua.ValueRankOneDimension,
		[]uint32{0},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.localeIds, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ActualSessionTimeout"),
		opcua.NewLocalizedText("ActualSessionTimeout", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDDouble,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(float64(s.timeout.Nanoseconds()/1000000), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "MaxResponseMessageSize"),
		opcua.NewLocalizedText("MaxResponseMessageSize", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDUInt32,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.maxResponseMessageSize, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ClientConnectionTime"),
		opcua.NewLocalizedText("ClientConnectionTime", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDDateTime,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.timeCreated, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ClientLastContactTime"),
		opcua.NewLocalizedText("ClientLastContactTime", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDDateTime,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.lastAccess, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "CurrentSubscriptionsCount"),
		opcua.NewLocalizedText("CurrentSubscriptionsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDUInt32,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(uint32(len(srv.subscriptionManager.GetBySession(s))), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "CurrentMonitoredItemsCount"),
		opcua.NewLocalizedText("CurrentMonitoredItemsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDUInt32,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		itemCount := 0
		subs := srv.subscriptionManager.GetBySession(s)
		for _, sub := range subs {
			itemCount += len(sub.items)
		}
		return opcua.NewDataValue(uint32(itemCount), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "CurrentPublishRequestsInQueue"),
		opcua.NewLocalizedText("CurrentPublishRequestsInQueue", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDUInt32,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(uint32(len(s.publishRequests)), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "TotalRequestCount"),
		opcua.NewLocalizedText("TotalRequestCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.requestCount, ErrorCount: s.errorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "UnauthorizedRequestCount"),
		opcua.NewLocalizedText("UnauthorizedRequestCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDUInt32,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.unauthorizedRequestCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ReadCount"),
		opcua.NewLocalizedText("ReadCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.readCount, ErrorCount: s.readErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "HistoryReadCount"),
		opcua.NewLocalizedText("HistoryReadCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.historyReadCount, ErrorCount: s.historyReadErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "WriteCount"),
		opcua.NewLocalizedText("WriteCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.writeCount, ErrorCount: s.writeErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "HistoryUpdateCount"),
		opcua.NewLocalizedText("HistoryUpdateCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.historyUpdateCount, ErrorCount: s.historyUpdateErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "CallCount"),
		opcua.NewLocalizedText("CallCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.callCount, ErrorCount: s.callErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "CreateMonitoredItemsCount"),
		opcua.NewLocalizedText("CreateMonitoredItemsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.createMonitoredItemsCount, ErrorCount: s.createMonitoredItemsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ModifyMonitoredItemsCount"),
		opcua.NewLocalizedText("ModifyMonitoredItemsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.modifyMonitoredItemsCount, ErrorCount: s.modifyMonitoredItemsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SetMonitoringModeCount"),
		opcua.NewLocalizedText("SetMonitoringModeCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.setMonitoringModeCount, ErrorCount: s.setMonitoringModeErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SetTriggeringCount"),
		opcua.NewLocalizedText("SetTriggeringCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.setTriggeringCount, ErrorCount: s.setTriggeringErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "DeleteMonitoredItemsCount"),
		opcua.NewLocalizedText("DeleteMonitoredItemsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.deleteMonitoredItemsCount, ErrorCount: s.deleteMonitoredItemsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "CreateSubscriptionCount"),
		opcua.NewLocalizedText("CreateSubscriptionCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.createSubscriptionCount, ErrorCount: s.createSubscriptionErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ModifySubscriptionCount"),
		opcua.NewLocalizedText("ModifySubscriptionCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.modifySubscriptionCount, ErrorCount: s.modifySubscriptionErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SetPublishingModeCount"),
		opcua.NewLocalizedText("SetPublishingModeCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.setPublishingModeCount, ErrorCount: s.setPublishingModeErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "PublishCount"),
		opcua.NewLocalizedText("PublishCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.publishCount, ErrorCount: s.publishErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "RepublishCount"),
		opcua.NewLocalizedText("RepublishCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.republishCount, ErrorCount: s.republishErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "TransferSubscriptionsCount"),
		opcua.NewLocalizedText("TransferSubscriptionsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.transferSubscriptionsCount, ErrorCount: s.transferSubscriptionsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "DeleteSubscriptionsCount"),
		opcua.NewLocalizedText("DeleteSubscriptionsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.deleteSubscriptionsCount, ErrorCount: s.deleteSubscriptionsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "AddNodesCount"),
		opcua.NewLocalizedText("AddNodesCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.addNodesCount, ErrorCount: s.addNodesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "AddReferencesCount"),
		opcua.NewLocalizedText("AddReferencesCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.addReferencesCount, ErrorCount: s.addReferencesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "DeleteNodesCount"),
		opcua.NewLocalizedText("DeleteNodesCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.deleteNodesCount, ErrorCount: s.deleteNodesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "DeleteReferencesCount"),
		opcua.NewLocalizedText("DeleteReferencesCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.deleteReferencesCount, ErrorCount: s.deleteReferencesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "BrowseCount"),
		opcua.NewLocalizedText("BrowseCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.browseCount, ErrorCount: s.browseErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "BrowseNextCount"),
		opcua.NewLocalizedText("BrowseNextCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.browseNextCount, ErrorCount: s.browseNextErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "TranslateBrowsePathsToNodeIdsCount"),
		opcua.NewLocalizedText("TranslateBrowsePathsToNodeIdsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.translateBrowsePathsToNodeIdsCount, ErrorCount: s.translateBrowsePathsToNodeIdsErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "QueryFirstCount"),
		opcua.NewLocalizedText("QueryFirstCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.queryFirstCount, ErrorCount: s.queryFirstErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "QueryNextCount"),
		opcua.NewLocalizedText("QueryNextCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.queryNextCount, ErrorCount: s.queryNextErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "RegisterNodesCount"),
		opcua.NewLocalizedText("RegisterNodesCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.registerNodesCount, ErrorCount: s.registerNodesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "UnregisterNodesCount"),
		opcua.NewLocalizedText("UnregisterNodesCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBaseDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(opcua.ServiceCounterDataType{TotalCount: s.unregisterNodesCount, ErrorCount: s.unregisterNodesErrorCount}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)

	// SessionSecurityDiagnostics
	sessionSecurityDiagnosticsVariable := NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SessionSecurityDiagnostics"),
		opcua.NewLocalizedText("SessionSecurityDiagnostics", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDSessionSecurityDiagnosticsType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsObject.NodeID())),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(opcua.VariableIDServerServerDiagnosticsSessionsDiagnosticsSummarySessionSecurityDiagnosticsArray)),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDSessionSecurityDiagnosticsDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	sessionSecurityDiagnosticsVariable.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == opcua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != opcua.MessageSecurityModeSignAndEncrypt {
			return opcua.NewDataValue(nil, opcua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return opcua.NewDataValue(opcua.SessionSecurityDiagnosticsDataType{
			SessionID:               s.sessionId,
			ClientUserIDOfSession:   s.clientUserIdOfSession,
			ClientUserIDHistory:     s.clientUserIdHistory,
			AuthenticationMechanism: s.authenticationMechanism,
			Encoding:                "UA Binary",
			TransportProtocol:       opcua.TransportProfileURIUaTcpTransport,
			SecurityMode:            ch.SecurityMode(),
			SecurityPolicyURI:       ch.SecurityPolicyURI(),
			ClientCertificate:       opcua.ByteString(ch.RemoteCertificate()),
		}, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, sessionSecurityDiagnosticsVariable)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SessionId"),
		opcua.NewLocalizedText("SessionId", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDNodeID,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == opcua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != opcua.MessageSecurityModeSignAndEncrypt {
			return opcua.NewDataValue(nil, opcua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return opcua.NewDataValue(s.sessionId, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ClientUserIdOfSession"),
		opcua.NewLocalizedText("ClientUserIdOfSession", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDString,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == opcua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != opcua.MessageSecurityModeSignAndEncrypt {
			return opcua.NewDataValue(nil, opcua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return opcua.NewDataValue(s.clientUserIdOfSession, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ClientUserIdHistory"),
		opcua.NewLocalizedText("ClientUserIdHistory", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDString,
		opcua.ValueRankOneDimension,
		[]uint32{0},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == opcua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != opcua.MessageSecurityModeSignAndEncrypt {
			return opcua.NewDataValue(nil, opcua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return opcua.NewDataValue(s.clientUserIdHistory, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "AuthenticationMechanism"),
		opcua.NewLocalizedText("AuthenticationMechanism", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDString,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == opcua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != opcua.MessageSecurityModeSignAndEncrypt {
			return opcua.NewDataValue(nil, opcua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return opcua.NewDataValue(s.authenticationMechanism, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "Encoding"),
		opcua.NewLocalizedText("Encoding", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDString,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == opcua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != opcua.MessageSecurityModeSignAndEncrypt {
			return opcua.NewDataValue(nil, opcua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return opcua.NewDataValue("UA Binary", 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "TransportProtocol"),
		opcua.NewLocalizedText("TransportProtocol", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDString,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == opcua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != opcua.MessageSecurityModeSignAndEncrypt {
			return opcua.NewDataValue(nil, opcua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return opcua.NewDataValue(opcua.TransportProfileURIUaTcpTransport, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SecurityMode"),
		opcua.NewLocalizedText("SecurityMode", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDMessageSecurityMode,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == opcua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != opcua.MessageSecurityModeSignAndEncrypt {
			return opcua.NewDataValue(nil, opcua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return opcua.NewDataValue(int32(ch.SecurityMode()), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SecurityPolicyURI"),
		opcua.NewLocalizedText("SecurityPolicyURI", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDString,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == opcua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != opcua.MessageSecurityModeSignAndEncrypt {
			return opcua.NewDataValue(nil, opcua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return opcua.NewDataValue(ch.SecurityPolicyURI(), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ClientCertificate"),
		opcua.NewLocalizedText("ClientCertificate", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionSecurityDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDByteString,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		session, ok := ctx.Value(SessionKey).(*Session)
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ok = false
		for _, n := range session.userRoles {
			if n == opcua.ObjectIDWellKnownRoleAuthenticatedUser {
				ok = true
			}
		}
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		ch, ok := srv.ChannelManager().Get(session.SecureChannelId())
		if !ok {
			return opcua.NewDataValue(nil, opcua.BadUserAccessDenied, time.Now(), 0, time.Now(), 0)
		}
		if ch.SecurityMode() != opcua.MessageSecurityModeSignAndEncrypt {
			return opcua.NewDataValue(nil, opcua.BadSecurityModeInsufficient, time.Now(), 0, time.Now(), 0)
		}
		return opcua.NewDataValue(opcua.ByteString(ch.RemoteCertificate()), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)

	// SubscriptionDiagnostics
	subscriptionDiagnosticsArrayVariable := NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SubscriptionDiagnosticsArray"),
		opcua.NewLocalizedText("SubscriptionDiagnosticsArray", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDSubscriptionDiagnosticsArrayType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(sessionDiagnosticsObject.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDSubscriptionDiagnosticsDataType,
		opcua.ValueRankOneDimension,
		[]uint32{0},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	subscriptionDiagnosticsArrayVariable.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue([]opcua.ExtensionObject{}, 0, time.Now(), 0, time.Now(), 0)
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
