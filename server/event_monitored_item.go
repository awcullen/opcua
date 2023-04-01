// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"sync/atomic"
	"time"

	"sync"

	"github.com/awcullen/opcua/ua"
	deque "github.com/gammazero/deque"
)

// EventMonitoredItem specifies a node that is monitored for events.
type EventMonitoredItem struct {
	sync.RWMutex
	id               uint32
	itemToMonitor    ua.ReadValueID
	monitoringMode   ua.MonitoringMode
	clientHandle     uint32
	samplingInterval float64
	queueSize        uint32
	discardOldest    bool
	queue            deque.Deque[[]ua.Variant]
	node             Node
	eventFilter      ua.EventFilter
	sub              *Subscription
	srv              *Server
	triggeredItems   []MonitoredItem
	triggered        bool
}

// NewEventMonitoredItem constructs a new EventMonitoredItem.
func NewEventMonitoredItem(sub *Subscription, node Node, itemToMonitor ua.ReadValueID, monitoringMode ua.MonitoringMode, parameters ua.MonitoringParameters) *EventMonitoredItem {
	mi := &EventMonitoredItem{
		sub:            sub,
		srv:            sub.manager.server,
		node:           node,
		id:             atomic.AddUint32(&monitoredItemID, 1),
		itemToMonitor:  itemToMonitor,
		monitoringMode: monitoringMode,
		clientHandle:   parameters.ClientHandle,
		discardOldest:  parameters.DiscardOldest,
		queue:          deque.Deque[[]ua.Variant]{},
	}
	mi.setQueueSize(parameters.QueueSize)
	mi.setSamplingInterval(parameters.SamplingInterval)
	mi.setFilter(parameters.Filter)

	mi.Lock()
	mi.startMonitoring()
	mi.Unlock()
	return mi
}

// ID returns the identifier of the MonitoredItem.
func (mi *EventMonitoredItem) ID() uint32 {
	return mi.id
}

// Node returns the Node of the MonitoredItem.
func (mi *EventMonitoredItem) Node() Node {
	return mi.node
}

// ItemToMonitor returns the ReadValueID of the MonitoredItem.
func (mi *EventMonitoredItem) ItemToMonitor() ua.ReadValueID {
	return mi.itemToMonitor
}

// SamplingInterval returns the sampling interval in ms of the MonitoredItem.
func (mi *EventMonitoredItem) SamplingInterval() float64 {
	mi.RLock()
	defer mi.RUnlock()
	return mi.samplingInterval
}

// QueueSize returns the queue size of the MonitoredItem.
func (mi *EventMonitoredItem) QueueSize() uint32 {
	mi.RLock()
	defer mi.RUnlock()
	return mi.queueSize
}

// MonitoringMode returns the monitoring mode of the MonitoredItem.
func (mi *EventMonitoredItem) MonitoringMode() ua.MonitoringMode {
	mi.RLock()
	defer mi.RUnlock()
	return mi.monitoringMode
}

// ClientHandle returns the client handle of the MonitoredItem.
func (mi *EventMonitoredItem) ClientHandle() uint32 {
	mi.RLock()
	defer mi.RUnlock()
	return mi.clientHandle
}

// Triggered returns true when the MonitoredItem is triggered.
func (mi *EventMonitoredItem) Triggered() bool {
	mi.RLock()
	defer mi.RUnlock()
	return mi.triggered
}

// SetTriggered sets when the MonitoredItem is triggered.
func (mi *EventMonitoredItem) SetTriggered(val bool) {
	mi.Lock()
	defer mi.Unlock()
	mi.triggered = val
}

// Modify modifies the MonitoredItem.
func (mi *EventMonitoredItem) Modify(req ua.MonitoredItemModifyRequest) ua.MonitoredItemModifyResult {
	mi.Lock()
	defer mi.Unlock()
	mi.stopMonitoring()
	mi.clientHandle = req.RequestedParameters.ClientHandle
	mi.discardOldest = req.RequestedParameters.DiscardOldest
	mi.setQueueSize(req.RequestedParameters.QueueSize)
	mi.setSamplingInterval(req.RequestedParameters.SamplingInterval)
	mi.setFilter(req.RequestedParameters.Filter)
	mi.startMonitoring()
	return ua.MonitoredItemModifyResult{RevisedSamplingInterval: mi.samplingInterval, RevisedQueueSize: mi.queueSize}
}

// Delete deletes the DataMonitoredItem.
func (mi *EventMonitoredItem) Delete() {
	mi.Lock()
	defer mi.Unlock()
	mi.stopMonitoring()
	mi.queue.Clear()
	mi.node = nil
	mi.sub = nil
	mi.triggeredItems = nil
}

// SetMonitoringMode sets the MonitoringMode of the MonitoredItem.
func (mi *EventMonitoredItem) SetMonitoringMode(mode ua.MonitoringMode) {
	mi.Lock()
	defer mi.Unlock()
	if mi.monitoringMode == mode {
		return
	}
	mi.stopMonitoring()
	mi.monitoringMode = mode
	if mode == ua.MonitoringModeDisabled {
		mi.queue.Clear()
		mi.sub.disabledMonitoredItemCount++
	} else {
		mi.sub.disabledMonitoredItemCount--
	}
	mi.startMonitoring()
}

func (mi *EventMonitoredItem) setQueueSize(queueSize uint32) {
	mi.queueSize = maxQueueSize

	// trim to size
	if mi.discardOldest {
		for mi.queue.Len() > int(mi.queueSize) {
			mi.queue.PopFront()
		}
	} else {
		for mi.queue.Len() > int(mi.queueSize) {
			mi.queue.PopBack()
		}
	}
}

func (mi *EventMonitoredItem) setSamplingInterval(samplingInterval float64) {
	mi.samplingInterval = 0
}

func (mi *EventMonitoredItem) setFilter(filter any) {
	if ef, ok := filter.(ua.EventFilter); ok {
		mi.eventFilter = ef
	} else {
		mi.eventFilter = ua.EventFilter{}
	}
}

func (mi *EventMonitoredItem) enqueue(item []ua.Variant) {
	overflow := false
	if mi.discardOldest {
		for mi.queue.Len() >= int(mi.queueSize) {
			mi.queue.PopFront() // discard oldest
			overflow = true
		}
		mi.queue.PushBack(item)
		if overflow && mi.queueSize > 1 {
			mi.sub.monitoringQueueOverflowCount++
		}
	} else {
		for mi.queue.Len() >= int(mi.queueSize) {
			mi.queue.PopBack() // discard newest
			overflow = true
		}
		mi.queue.PushBack(item)
		if overflow && mi.queueSize > 1 {
			mi.sub.monitoringQueueOverflowCount++
		}
	}
	if mi.triggeredItems != nil {
		for _, item := range mi.triggeredItems {
			item.SetTriggered(true)
			// log.Printf("Item %d triggered %d", mi.id, item.id)
		}
	}
}

func (mi *EventMonitoredItem) OnEvent(evt ua.Event) {
	mi.Lock()
	if res, ok := mi.whereClause(evt, 0).(bool); ok && res {
		mi.enqueue(mi.selectFields(evt))
	}
	mi.Unlock()
}

var (
	attributeOperandEventType = ua.SimpleAttributeOperand{TypeDefinitionID: ua.ObjectTypeIDBaseEventType, BrowsePath: ua.ParseBrowsePath("EventType"), AttributeID: ua.AttributeIDValue}
)

func (mi *EventMonitoredItem) whereClause(evt ua.Event, idx int) any {
	if idx >= len(mi.eventFilter.WhereClause.Elements) {
		return true
	}
	element := mi.eventFilter.WhereClause.Elements[idx]
	switch element.FilterOperator {

	case ua.FilterOperatorEquals:
		var a, b ua.Variant
		switch c := element.FilterOperands[0].(type) {
		case ua.LiteralOperand:
			a = c.Value
		case ua.SimpleAttributeOperand:
			a = evt.GetAttribute(c)
		case ua.ElementOperand:
			a = mi.whereClause(evt, int(c.Index))
		default:
			return false
		}
		switch c := element.FilterOperands[1].(type) {
		case ua.LiteralOperand:
			b = c.Value
		case ua.SimpleAttributeOperand:
			b = evt.GetAttribute(c)
		case ua.ElementOperand:
			b = mi.whereClause(evt, int(c.Index))
		default:
			return false
		}
		return a == b

	case ua.FilterOperatorOfType:
		if a, ok := element.FilterOperands[0].(ua.LiteralOperand); ok {
			if b, ok := a.Value.(ua.NodeID); ok {
				if c, ok := evt.GetAttribute(attributeOperandEventType).(ua.NodeID); ok {
					if c == b || mi.srv.namespaceManager.IsSubtype(c, b) {
						return true
					}
				}
			}
		}
		return false

	default:
		return false
	}
}

func (mi *EventMonitoredItem) selectFields(evt ua.Event) []ua.Variant {
	clauses := mi.eventFilter.SelectClauses
	ret := make([]ua.Variant, len(clauses))
	for i, clause := range clauses {
		ret[i] = evt.GetAttribute(clause)
	}
	return ret
}

func (mi *EventMonitoredItem) startMonitoring() {
	if mi.monitoringMode == ua.MonitoringModeDisabled {
		return
	}
	if n2, ok := mi.node.(*ObjectNode); ok {
		n2.AddEventListener(mi)
	}
}

func (mi *EventMonitoredItem) stopMonitoring() {
	if n2, ok := mi.node.(*ObjectNode); ok {
		n2.RemoveEventListener(mi)
	}
}

func (mi *EventMonitoredItem) notifications(max int) (notifications []any, more bool) {
	mi.Lock()
	defer mi.Unlock()
	notifications = make([]any, 0, 4)
	for i := 0; i < max; i++ {
		if mi.queue.Len() > 0 {
			notifications = append(notifications, mi.queue.PopFront())
		} else {
			break
		}
	}
	more = mi.queue.Len() > 0
	if mi.triggered && !more {
		mi.triggered = false
		// log.Printf("Reset triggered %d", mi.id)
	}
	return notifications, more
}

func (mi *EventMonitoredItem) notificationsAvailable(tn time.Time, late bool, resend bool) bool {
	_ = late
	mi.Lock()
	defer mi.Unlock()
	// if disabled, then report false.
	if mi.monitoringMode == ua.MonitoringModeDisabled {
		return false
	}

	return mi.queue.Len() > 0 && (mi.monitoringMode == ua.MonitoringModeReporting || mi.triggered)
}

// AddTriggeredItem adds a item to be triggered by this item.
func (mi *EventMonitoredItem) AddTriggeredItem(item MonitoredItem) bool {
	mi.Lock()
	mi.triggeredItems = append(mi.triggeredItems, item)
	mi.Unlock()
	return true
}

// RemoveTriggeredItem removes an item to be triggered by this item.
func (mi *EventMonitoredItem) RemoveTriggeredItem(item MonitoredItem) bool {
	mi.Lock()
	ret := false
	for i, e := range mi.triggeredItems {
		if e.ID() == item.ID() {
			mi.triggeredItems[i] = mi.triggeredItems[len(mi.triggeredItems)-1]
			mi.triggeredItems[len(mi.triggeredItems)-1] = nil
			mi.triggeredItems = mi.triggeredItems[:len(mi.triggeredItems)-1]
			ret = true
			break
		}
	}
	mi.Unlock()
	return ret
}
