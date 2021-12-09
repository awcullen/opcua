package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/awcullen/opcua/ua"
	"github.com/google/uuid"
)

// SubscriptionManager manages the subscriptions for a server.
type SubscriptionManager struct {
	sync.RWMutex
	server            *Server
	subscriptionsByID map[uint32]*Subscription
}

// NewSubscriptionManager instantiates a new SubscriptionManager.
func NewSubscriptionManager(server *Server) *SubscriptionManager {
	m := &SubscriptionManager{server: server, subscriptionsByID: make(map[uint32]*Subscription)}
	go func(m *SubscriptionManager) {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.checkForExpiredSubscriptions()
			case <-m.server.closing:
				m.RLock()
				for _, v := range m.subscriptionsByID {
					v.stopPublishing()
				}
				m.RUnlock()
				return
			}
		}
	}(m)
	return m
}

// Get a subscription from the server.
func (m *SubscriptionManager) Get(id uint32) (*Subscription, bool) {
	m.RLock()
	defer m.RUnlock()
	if s, ok := m.subscriptionsByID[id]; ok {
		return s, ok
	}
	return nil, false
}

// Add a subscription to the server.
func (m *SubscriptionManager) Add(s *Subscription) error {
	m.Lock()
	defer m.Unlock()
	maxSubscriptionCount := m.server.MaxSubscriptionCount()
	if maxSubscriptionCount > 0 && len(m.subscriptionsByID) >= int(maxSubscriptionCount) {
		return ua.BadTooManySubscriptions
	}
	m.subscriptionsByID[s.id] = s
	if m.server.serverDiagnostics {
		m.addDiagnosticsNode(s)
		m.server.serverDiagnosticsSummary.CumulatedSubscriptionCount++
		m.server.serverDiagnosticsSummary.CurrentSubscriptionCount = uint32(len(m.subscriptionsByID))
	}
	return nil
}

// Delete the subscription from the server.
func (m *SubscriptionManager) Delete(s *Subscription) {
	m.Lock()
	defer m.Unlock()
	delete(m.subscriptionsByID, s.id)
	if m.server.serverDiagnostics {
		m.removeDiagnosticsNode(s)
		m.server.serverDiagnosticsSummary.CurrentSubscriptionCount = uint32(len(m.subscriptionsByID))
	}
}

// Len returns the number of subscriptions.
func (m *SubscriptionManager) Len() int {
	m.RLock()
	defer m.RUnlock()
	return len(m.subscriptionsByID)
}

// GetBySession returns subscriptions for the session.
func (m *SubscriptionManager) GetBySession(session *Session) []*Subscription {
	m.RLock()
	defer m.RUnlock()
	subs := make([]*Subscription, 0, 4)
	for _, sub := range m.subscriptionsByID {
		if sub.session == session {
			subs = append(subs, sub)
		}
	}
	return subs
}

func (m *SubscriptionManager) checkForExpiredSubscriptions() {
	m.Lock()
	defer m.Unlock()
	for k, s := range m.subscriptionsByID {
		if s.IsExpired() {
			delete(m.subscriptionsByID, k)
			if m.server.serverDiagnostics {
				// remove diagnostic node
				nm := m.server.NamespaceManager()
				if n, ok := nm.FindNode(s.diagnosticsNodeId); ok {
					nm.DeleteNode(n, true)
				}
				m.server.Lock()
				m.server.serverDiagnosticsSummary.CurrentSubscriptionCount = uint32(len(m.subscriptionsByID))
				m.server.Unlock()
			}
			// log.Printf("Deleted expired subscription '%d'.\n", k)
			s.Delete()
		}
	}
}

func (m *SubscriptionManager) addDiagnosticsNode(s *Subscription) {
	srv := m.server
	nm := srv.NamespaceManager()
	nodes := []Node{}

	refs := []ua.Reference{
		ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDSubscriptionDiagnosticsType)),
		ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(ua.VariableIDServerServerDiagnosticsSubscriptionDiagnosticsArray)),
	}
	if n1, ok := nm.FindNode(s.sessionId); ok {
		if n2, ok := nm.FindComponent(n1, ua.NewQualifiedName(0, "SubscriptionDiagnosticsArray")); ok {
			refs = append(refs, ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(n2.NodeID())))
		}
	}
	subscriptionDiagnosticsVariable := NewVariableNode(
		s.diagnosticsNodeId,
		ua.NewQualifiedName(uint16(1), fmt.Sprint(s.id)),
		ua.NewLocalizedText(fmt.Sprint(s.id), ""),
		ua.NewLocalizedText("", ""),
		nil,
		refs,
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDSubscriptionDiagnosticsDataType,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	subscriptionDiagnosticsVariable.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		s.RLock()
		defer s.RUnlock()
		dv := ua.NewDataValue(ua.SubscriptionDiagnosticsDataType{
				SessionID:                  s.sessionId,
				SubscriptionID:             s.id,
				Priority:                   s.priority,
				PublishingInterval:         s.publishingInterval,
				MaxKeepAliveCount:          s.maxKeepAliveCount,
				MaxLifetimeCount:           s.lifetimeCount,
				MaxNotificationsPerPublish: s.maxNotificationsPerPublish,
				PublishingEnabled:          s.publishingEnabled,
				ModifyCount:                s.modifyCount,
				// EnableCount:                  uint32(0),
				// DisableCount:                 uint32(0),
				RepublishRequestCount:        s.republishRequestCount,
				RepublishMessageRequestCount: s.republishMessageRequestCount,
				RepublishMessageCount:        s.republishMessageCount,
				// TransferRequestCount:         uint32(0),
				// TransferredToAltClientCount:  uint32(0),
				// TransferredToSameClientCount: uint32(0),
				PublishRequestCount:          s.publishRequestCount,
				DataChangeNotificationsCount: s.dataChangeNotificationsCount,
				EventNotificationsCount:      s.eventNotificationsCount,
				NotificationsCount:           s.notificationsCount,
				LatePublishRequestCount:      s.latePublishRequestCount,
				CurrentKeepAliveCount:        s.keepAliveCounter,
				CurrentLifetimeCount:         s.lifetimeCounter,
				UnacknowledgedMessageCount:   s.unacknowledgedMessageCount,
				// DiscardedMessageCount:        uint32(0),
				MonitoredItemCount:           s.monitoredItemCount,
				DisabledMonitoredItemCount:   s.disabledMonitoredItemCount,
				MonitoringQueueOverflowCount: s.monitoringQueueOverflowCount,
				NextSequenceNumber:           s.seqNum,
				// EventQueueOverFlowCount:      uint32(0),
			}, 0, time.Now(), 0, time.Now(), 0)
		return dv
	})
	nodes = append(nodes, subscriptionDiagnosticsVariable)
	n := NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "SessionId"),
		ua.NewLocalizedText("SessionId", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		ua.NewQualifiedName(0, "SubscriptionId"),
		ua.NewLocalizedText("SubscriptionId", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.id, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "Priority"),
		ua.NewLocalizedText("Priority", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDByte,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.priority, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "PublishingInterval"),
		ua.NewLocalizedText("PublishingInterval", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.publishingInterval, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "MaxKeepAliveCount"),
		ua.NewLocalizedText("MaxKeepAliveCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.maxKeepAliveCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "MaxLifetimeCount"),
		ua.NewLocalizedText("MaxLifetimeCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.lifetimeCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "MaxNotificationsPerPublish"),
		ua.NewLocalizedText("MaxNotificationsPerPublish", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.maxNotificationsPerPublish, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "PublishingEnabled"),
		ua.NewLocalizedText("PublishingEnabled", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
		},
		ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		ua.DataTypeIDBoolean,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req ua.ReadValueID) ua.DataValue {
		return ua.NewDataValue(s.publishingEnabled, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "ModifyCount"),
		ua.NewLocalizedText("ModifyCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.modifyCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "EnableCount"),
		ua.NewLocalizedText("EnableCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "DisableCount"),
		ua.NewLocalizedText("DisableCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "RepublishRequestCount"),
		ua.NewLocalizedText("RepublishRequestCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.republishRequestCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "RepublishMessageRequestCount"),
		ua.NewLocalizedText("RepublishMessageRequestCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.republishMessageRequestCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "RepublishMessageCount"),
		ua.NewLocalizedText("RepublishMessageCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.republishMessageCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "TransferRequestCount"),
		ua.NewLocalizedText("TransferRequestCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "TransferredToAltClientCount"),
		ua.NewLocalizedText("TransferredToAltClientCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "TransferredToSameClientCount"),
		ua.NewLocalizedText("TransferredToSameClientCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "PublishRequestCount"),
		ua.NewLocalizedText("PublishRequestCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.publishRequestCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "DataChangeNotificationsCount"),
		ua.NewLocalizedText("DataChangeNotificationsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.dataChangeNotificationsCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "EventNotificationsCount"),
		ua.NewLocalizedText("EventNotificationsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.eventNotificationsCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "NotificationsCount"),
		ua.NewLocalizedText("NotificationsCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.notificationsCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "LatePublishRequestCount"),
		ua.NewLocalizedText("LatePublishRequestCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.latePublishRequestCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "CurrentKeepAliveCount"),
		ua.NewLocalizedText("CurrentKeepAliveCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.keepAliveCounter, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "CurrentLifetimeCount"),
		ua.NewLocalizedText("CurrentLifetimeCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.lifetimeCounter, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "UnacknowledgedMessageCount"),
		ua.NewLocalizedText("UnacknowledgedMessageCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.unacknowledgedMessageCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "DiscardedMessageCount"),
		ua.NewLocalizedText("DiscardedMessageCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "MonitoredItemCount"),
		ua.NewLocalizedText("MonitoredItemCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.monitoredItemCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "DisabledMonitoredItemCount"),
		ua.NewLocalizedText("DisabledMonitoredItemCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.disabledMonitoredItemCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "MonitoringQueueOverflowCount"),
		ua.NewLocalizedText("MonitoringQueueOverflowCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.monitoringQueueOverflowCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "NextSequenceNumber"),
		ua.NewLocalizedText("NextSequenceNumber", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(s.seqNum, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		ua.NewNodeIDGUID(1, uuid.New()),
		ua.NewQualifiedName(0, "EventQueueOverFlowCount"),
		ua.NewLocalizedText("EventQueueOverFlowCount", ""),
		ua.NewLocalizedText("", ""),
		nil,
		[]ua.Reference{
			ua.NewReference(ua.ReferenceTypeIDHasTypeDefinition, false, ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)),
			ua.NewReference(ua.ReferenceTypeIDHasComponent, true, ua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return ua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)

	err := nm.AddNodes(nodes)
	if err != nil {
		log.Printf("Error adding session diagnostics objects.\n")
	}
}

func (m *SubscriptionManager) removeDiagnosticsNode(s *Subscription) {
	nm := m.server.NamespaceManager()
	if n, ok := nm.FindNode(s.diagnosticsNodeId); ok {
		nm.DeleteNode(n, true)
	}
}
