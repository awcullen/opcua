package server

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/awcullen/opcua"
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
		return opcua.BadTooManySubscriptions
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

	refs := []opcua.Reference{
		opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDSubscriptionDiagnosticsType)),
		opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(opcua.VariableIDServerServerDiagnosticsSubscriptionDiagnosticsArray)),
	}
	if n1, ok := nm.FindNode(s.sessionId); ok {
		if n2, ok := nm.FindComponent(n1, opcua.NewQualifiedName(0, "SubscriptionDiagnosticsArray")); ok {
			refs = append(refs, opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(n2.NodeID())))
		}
	}
	subscriptionDiagnosticsVariable := NewVariableNode(
		s.diagnosticsNodeId,
		opcua.NewQualifiedName(uint16(1), fmt.Sprint(s.id)),
		opcua.NewLocalizedText(fmt.Sprint(s.id), ""),
		opcua.NewLocalizedText("", ""),
		nil,
		refs,
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDSubscriptionDiagnosticsDataType,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	subscriptionDiagnosticsVariable.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		s.RLock()
		defer s.RUnlock()
		dv := opcua.NewDataValue(opcua.SubscriptionDiagnosticsDataType{
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
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "SessionId"),
		opcua.NewLocalizedText("SessionId", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		opcua.NewQualifiedName(0, "SubscriptionId"),
		opcua.NewLocalizedText("SubscriptionId", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.id, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "Priority"),
		opcua.NewLocalizedText("Priority", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDByte,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.priority, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "PublishingInterval"),
		opcua.NewLocalizedText("PublishingInterval", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.publishingInterval, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "MaxKeepAliveCount"),
		opcua.NewLocalizedText("MaxKeepAliveCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.maxKeepAliveCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "MaxLifetimeCount"),
		opcua.NewLocalizedText("MaxLifetimeCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.lifetimeCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "MaxNotificationsPerPublish"),
		opcua.NewLocalizedText("MaxNotificationsPerPublish", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.maxNotificationsPerPublish, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "PublishingEnabled"),
		opcua.NewLocalizedText("PublishingEnabled", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
		},
		opcua.NewDataValue(nil, opcua.BadWaitingForInitialData, time.Now(), 0, time.Now(), 0),
		opcua.DataTypeIDBoolean,
		opcua.ValueRankScalar,
		[]uint32{},
		opcua.AccessLevelsCurrentRead,
		125,
		false,
	)
	n.SetReadValueHandler(func(ctx context.Context, req opcua.ReadValueID) opcua.DataValue {
		return opcua.NewDataValue(s.publishingEnabled, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "ModifyCount"),
		opcua.NewLocalizedText("ModifyCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.modifyCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "EnableCount"),
		opcua.NewLocalizedText("EnableCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "DisableCount"),
		opcua.NewLocalizedText("DisableCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "RepublishRequestCount"),
		opcua.NewLocalizedText("RepublishRequestCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.republishRequestCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "RepublishMessageRequestCount"),
		opcua.NewLocalizedText("RepublishMessageRequestCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.republishMessageRequestCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "RepublishMessageCount"),
		opcua.NewLocalizedText("RepublishMessageCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.republishMessageCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "TransferRequestCount"),
		opcua.NewLocalizedText("TransferRequestCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "TransferredToAltClientCount"),
		opcua.NewLocalizedText("TransferredToAltClientCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "TransferredToSameClientCount"),
		opcua.NewLocalizedText("TransferredToSameClientCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "PublishRequestCount"),
		opcua.NewLocalizedText("PublishRequestCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.publishRequestCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "DataChangeNotificationsCount"),
		opcua.NewLocalizedText("DataChangeNotificationsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.dataChangeNotificationsCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "EventNotificationsCount"),
		opcua.NewLocalizedText("EventNotificationsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.eventNotificationsCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "NotificationsCount"),
		opcua.NewLocalizedText("NotificationsCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.notificationsCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "LatePublishRequestCount"),
		opcua.NewLocalizedText("LatePublishRequestCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.latePublishRequestCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "CurrentKeepAliveCount"),
		opcua.NewLocalizedText("CurrentKeepAliveCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.keepAliveCounter, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "CurrentLifetimeCount"),
		opcua.NewLocalizedText("CurrentLifetimeCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.lifetimeCounter, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "UnacknowledgedMessageCount"),
		opcua.NewLocalizedText("UnacknowledgedMessageCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.unacknowledgedMessageCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "DiscardedMessageCount"),
		opcua.NewLocalizedText("DiscardedMessageCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "MonitoredItemCount"),
		opcua.NewLocalizedText("MonitoredItemCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.monitoredItemCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "DisabledMonitoredItemCount"),
		opcua.NewLocalizedText("DisabledMonitoredItemCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.disabledMonitoredItemCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "MonitoringQueueOverflowCount"),
		opcua.NewLocalizedText("MonitoringQueueOverflowCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.monitoringQueueOverflowCount, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "NextSequenceNumber"),
		opcua.NewLocalizedText("NextSequenceNumber", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(s.seqNum, 0, time.Now(), 0, time.Now(), 0)
	})
	nodes = append(nodes, n)
	n = NewVariableNode(
		opcua.NewNodeIDGUID(1, uuid.New()),
		opcua.NewQualifiedName(0, "EventQueueOverFlowCount"),
		opcua.NewLocalizedText("EventQueueOverFlowCount", ""),
		opcua.NewLocalizedText("", ""),
		nil,
		[]opcua.Reference{
			opcua.NewReference(opcua.ReferenceTypeIDHasTypeDefinition, false, opcua.NewExpandedNodeID(opcua.VariableTypeIDBaseDataVariableType)),
			opcua.NewReference(opcua.ReferenceTypeIDHasComponent, true, opcua.NewExpandedNodeID(subscriptionDiagnosticsVariable.NodeID())),
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
		return opcua.NewDataValue(uint32(0), 0, time.Now(), 0, time.Now(), 0)
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
