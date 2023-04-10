// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"bytes"
	"math"
	"reflect"
	"sync/atomic"
	"time"

	"sync"

	"github.com/awcullen/opcua/ua"
	deque "github.com/gammazero/deque"
)

// DataChangeMonitoredItem specifies the node and attribute that is monitored for data changes.
type DataChangeMonitoredItem struct {
	sync.RWMutex
	id                  uint32
	itemToMonitor       ua.ReadValueID
	monitoringMode      ua.MonitoringMode
	clientHandle        uint32
	samplingInterval    float64
	queueSize           uint32
	discardOldest       bool
	timestampsToReturn  ua.TimestampsToReturn
	minSamplingInterval float64
	queue               deque.Deque[ua.DataValue]
	node                Node
	dataChangeFilter    ua.DataChangeFilter
	previousQueuedValue ua.DataValue
	sub                 *Subscription
	srv                 *Server
	prequeue            deque.Deque[ua.DataValue]
	ts                  time.Time
	ti                  time.Duration
	triggeredItems      []MonitoredItem
	triggered           bool
}

// NewDataChangeMonitoredItem constructs a new DataChangeMonitoredItem.
func NewDataChangeMonitoredItem(sub *Subscription, node Node, itemToMonitor ua.ReadValueID, monitoringMode ua.MonitoringMode, parameters ua.MonitoringParameters, timestampsToReturn ua.TimestampsToReturn, minSamplingInterval float64) *DataChangeMonitoredItem {
	mi := &DataChangeMonitoredItem{
		sub:                 sub,
		srv:                 sub.manager.server,
		node:                node,
		id:                  atomic.AddUint32(&monitoredItemID, 1),
		itemToMonitor:       itemToMonitor,
		monitoringMode:      monitoringMode,
		clientHandle:        parameters.ClientHandle,
		discardOldest:       parameters.DiscardOldest,
		timestampsToReturn:  timestampsToReturn,
		minSamplingInterval: minSamplingInterval,
		queue:               deque.Deque[ua.DataValue]{},
		prequeue:            deque.Deque[ua.DataValue]{},
		previousQueuedValue: ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Time{}, 0, time.Time{}, 0),
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
func (mi *DataChangeMonitoredItem) ID() uint32 {
	return mi.id
}

// Node returns the Node of the MonitoredItem.
func (mi *DataChangeMonitoredItem) Node() Node {
	return mi.node
}

// ItemToMonitor returns the ReadValueID of the MonitoredItem.
func (mi *DataChangeMonitoredItem) ItemToMonitor() ua.ReadValueID {
	return mi.itemToMonitor
}

// SamplingInterval returns the sampling interval in ms of the MonitoredItem.
func (mi *DataChangeMonitoredItem) SamplingInterval() float64 {
	mi.RLock()
	defer mi.RUnlock()
	return mi.samplingInterval
}

// QueueSize returns the queue size of the MonitoredItem.
func (mi *DataChangeMonitoredItem) QueueSize() uint32 {
	mi.RLock()
	defer mi.RUnlock()
	return mi.queueSize
}

// MonitoringMode returns the monitoring mode of the MonitoredItem.
func (mi *DataChangeMonitoredItem) MonitoringMode() ua.MonitoringMode {
	mi.RLock()
	defer mi.RUnlock()
	return mi.monitoringMode
}

// ClientHandle returns the client handle of the MonitoredItem.
func (mi *DataChangeMonitoredItem) ClientHandle() uint32 {
	mi.RLock()
	defer mi.RUnlock()
	return mi.clientHandle
}

// Triggered returns true when the MonitoredItem is triggered.
func (mi *DataChangeMonitoredItem) Triggered() bool {
	mi.RLock()
	defer mi.RUnlock()
	return mi.triggered
}

// SetTriggered sets when the MonitoredItem is triggered.
func (mi *DataChangeMonitoredItem) SetTriggered(val bool) {
	mi.Lock()
	defer mi.Unlock()
	mi.triggered = val
}

// Modify modifies the MonitoredItem.
func (mi *DataChangeMonitoredItem) Modify(req ua.MonitoredItemModifyRequest) ua.MonitoredItemModifyResult {
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
func (mi *DataChangeMonitoredItem) Delete() {
	mi.Lock()
	defer mi.Unlock()
	mi.stopMonitoring()
	mi.queue.Clear()
	mi.node = nil
	mi.previousQueuedValue = ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Time{}, 0, time.Time{}, 0)
	mi.sub = nil
	mi.prequeue.Clear()
	mi.triggeredItems = nil
}

// SetMonitoringMode sets the MonitoringMode of the MonitoredItem.
func (mi *DataChangeMonitoredItem) SetMonitoringMode(mode ua.MonitoringMode) {
	mi.Lock()
	defer mi.Unlock()
	if mi.monitoringMode == mode {
		return
	}
	mi.stopMonitoring()
	mi.monitoringMode = mode
	if mode == ua.MonitoringModeDisabled {
		mi.queue.Clear()
		mi.previousQueuedValue = ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Time{}, 0, time.Time{}, 0)
		mi.sub.disabledMonitoredItemCount++
	} else {
		mi.sub.disabledMonitoredItemCount--
	}
	mi.startMonitoring()
}

func (mi *DataChangeMonitoredItem) setQueueSize(queueSize uint32) {
	if queueSize > maxQueueSize {
		queueSize = maxQueueSize
	}
	if queueSize < 1 {
		queueSize = 1
	}
	mi.queueSize = queueSize

	// trim to size
	overflow := false
	if mi.discardOldest {
		for mi.queue.Len() > int(mi.queueSize) {
			mi.queue.PopFront()
			overflow = true
		}
		if overflow && mi.queue.Len() > 1 {
			// set overflow bit of statuscode
			v := mi.queue.Front()
			v.StatusCode = ua.StatusCode(uint32(v.StatusCode) | ua.InfoTypeDataValue | ua.Overflow)
		}
	} else {
		for mi.queue.Len() > int(mi.queueSize) {
			mi.queue.PopBack()
			overflow = true
		}
		if overflow && mi.queue.Len() > 1 {
			// set overflow bit of statuscode
			v := mi.queue.Back()
			v.StatusCode = ua.StatusCode(uint32(v.StatusCode) | ua.InfoTypeDataValue | ua.Overflow)
		}
	}
}

func (mi *DataChangeMonitoredItem) setSamplingInterval(samplingInterval float64) {
	switch mi.itemToMonitor.AttributeID {
	case ua.AttributeIDValue:
		if samplingInterval < 0 {
			samplingInterval = mi.sub.publishingInterval
		}
		if samplingInterval < mi.minSamplingInterval {
			samplingInterval = mi.minSamplingInterval
		}
		if samplingInterval > maxSamplingInterval {
			samplingInterval = maxSamplingInterval
		}
		if v, ok := mi.node.(*VariableNode); ok {
			if min := v.MinimumSamplingInterval(); samplingInterval < min {
				samplingInterval = min
			}
		}
	default:
		if samplingInterval < 0 {
			samplingInterval = mi.sub.publishingInterval
		}
		if samplingInterval < mi.minSamplingInterval {
			samplingInterval = mi.minSamplingInterval
		}
		if samplingInterval > maxSamplingInterval {
			samplingInterval = maxSamplingInterval
		}
	}
	mi.samplingInterval = samplingInterval
	mi.ti = time.Duration(mi.samplingInterval) * time.Millisecond
}

func (mi *DataChangeMonitoredItem) setFilter(filter any) {
	if dcf, ok := filter.(ua.DataChangeFilter); ok {
		mi.dataChangeFilter = dcf
	} else {
		mi.dataChangeFilter = ua.DataChangeFilter{Trigger: ua.DataChangeTriggerStatusValue}
	}
}

func (mi *DataChangeMonitoredItem) startMonitoring() {
	mi.ts = time.Now()
	if mi.monitoringMode == ua.MonitoringModeDisabled {
		return
	}
	v := mi.srv.readValue(mi.sub.session, mi.itemToMonitor)
	mi.prequeue.PushBack(v)
	mi.Unlock()
	mi.srv.Scheduler().GetPollGroup(time.Duration(mi.samplingInterval) * time.Millisecond).Subscribe(mi)
	mi.Lock()
}

func (mi *DataChangeMonitoredItem) stopMonitoring() {
	mi.Unlock()
	mi.srv.Scheduler().GetPollGroup(time.Duration(mi.samplingInterval) * time.Millisecond).Unsubscribe(mi)
	mi.Lock()
}

// Poll reads the value of the itemToMonitor.
func (mi *DataChangeMonitoredItem) Poll() {
	mi.Lock()
	if n := mi.node; n != nil {
		v := mi.srv.readValue(mi.sub.session, mi.itemToMonitor)
		mi.prequeue.PushBack(v)
	}
	mi.Unlock()
}

// AddTriggeredItem adds a item to be triggered by this item.
func (mi *DataChangeMonitoredItem) AddTriggeredItem(item MonitoredItem) bool {
	mi.Lock()
	mi.triggeredItems = append(mi.triggeredItems, item)
	mi.Unlock()
	return true
}

// RemoveTriggeredItem removes an item to be triggered by this item.
func (mi *DataChangeMonitoredItem) RemoveTriggeredItem(item MonitoredItem) bool {
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

func (mi *DataChangeMonitoredItem) enqueue(item ua.DataValue) {
	overflow := false
	if mi.discardOldest {
		for mi.queue.Len() >= int(mi.queueSize) {
			mi.queue.PopFront() // discard oldest
			overflow = true
		}
		mi.queue.PushBack(item)
		if overflow && mi.queueSize > 1 {
			// set overflow bit of statuscode
			v := mi.queue.Front()
			v.StatusCode = ua.StatusCode(uint32(v.StatusCode) | ua.InfoTypeDataValue | ua.Overflow)
			mi.sub.monitoringQueueOverflowCount++
		}
	} else {
		for mi.queue.Len() >= int(mi.queueSize) {
			mi.queue.PopBack() // discard newest
			overflow = true
		}
		mi.queue.PushBack(item)
		if overflow && mi.queueSize > 1 {
			// set overflow bit of statuscode
			v := mi.queue.Back()
			v.StatusCode = ua.StatusCode(uint32(v.StatusCode) | ua.InfoTypeDataValue | ua.Overflow)
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

func (mi *DataChangeMonitoredItem) notifications(max int) (notifications []any, more bool) {
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

func (mi *DataChangeMonitoredItem) notificationsAvailable(tn time.Time, late bool, resend bool) bool {
	_ = late
	mi.Lock()
	defer mi.Unlock()
	// if disabled, then report false.
	if mi.monitoringMode == ua.MonitoringModeDisabled {
		mi.ts = tn
		return false
	}
	// update queue and report if queue has notifications available.
	// if in sampling interval mode, queue the last value of each sampling interval
	if mi.ti > 0 {
		// log.Printf("Sample from %s to %s", mi.ts.Add(-mi.ti).Format(time.StampMilli), tn.Format(time.StampMilli))
		v := mi.previousQueuedValue
		// for each interval
		for ; !mi.ts.After(tn); mi.ts = mi.ts.Add(mi.ti) {
			// for each value in prequeue
			for mi.prequeue.Len() > 0 {
				// peek
				peek := mi.prequeue.Front()
				// if timestamp is within sampling interval
				if !peek.ServerTimestamp.After(mi.ts) {
					v = peek
					mi.prequeue.PopFront()
					// log.Printf("Peek at %s take %s", mi.ts.Format(time.StampMilli), peek.ServerTimestamp.Format(time.StampMilli))
				} else {
					// log.Printf("Peek at %s leave %s", mi.ts.Format(time.StampMilli), peek.ServerTimestamp.Format(time.StampMilli))
					break
				}
			}
			// holding latest sample in v, enqueue it
			// v.ServerTimestamp = mi.ts
			// v.ServerPicoseconds = 0
			if mi.isDataChange(v, mi.previousQueuedValue) {
				mi.enqueue(withTimestamps(v, mi.timestampsToReturn))
				mi.previousQueuedValue = v
			}
		}
	} else {
		// for each value in prequeue
		for mi.prequeue.Len() > 0 {
			v := mi.prequeue.PopFront()
			if mi.isDataChange(v, mi.previousQueuedValue) {
				mi.enqueue(withTimestamps(v, mi.timestampsToReturn))
				mi.previousQueuedValue = v
			}
		}
	}
	if resend && mi.monitoringMode == ua.MonitoringModeReporting {
		if mi.queue.Len() == 0 {
			v := mi.srv.readValue(mi.sub.session, mi.itemToMonitor)
			mi.enqueue(withTimestamps(v, mi.timestampsToReturn))
			mi.previousQueuedValue = v
		}
	}
	return mi.queue.Len() > 0 && (mi.monitoringMode == ua.MonitoringModeReporting || mi.triggered)
}

func (mi *DataChangeMonitoredItem) isDataChange(current, previous ua.DataValue) bool {
	dcf := mi.dataChangeFilter
	switch dcf.Trigger {
	case ua.DataChangeTriggerStatus:
		return (current.StatusCode&0xFFFFF000 != previous.StatusCode&0xFFFFF000)
	case ua.DataChangeTriggerStatusValue:
		if current.StatusCode&0xFFFFF000 != previous.StatusCode&0xFFFFF000 {
			return true
		}
		switch ua.DeadbandType(dcf.DeadbandType) {
		case ua.DeadbandTypeNone:
			return !reflect.DeepEqual(current.Value, previous.Value)
		case ua.DeadbandTypeAbsolute:
			return !equalDeadbandAbsolute(current.Value, previous.Value, dcf.DeadbandValue)
		case ua.DeadbandTypePercent:
			return true
		}
	case ua.DataChangeTriggerStatusValueTimestamp:
		if current.StatusCode&0xFFFFF000 != previous.StatusCode&0xFFFFF000 {
			return true
		}
		if current.SourceTimestamp != previous.SourceTimestamp {
			return true
		}
		switch ua.DeadbandType(dcf.DeadbandType) {
		case ua.DeadbandTypeNone:
			return !reflect.DeepEqual(current.Value, previous.Value)
		case ua.DeadbandTypeAbsolute:
			return !equalDeadbandAbsolute(current.Value, previous.Value, dcf.DeadbandValue)
		case ua.DeadbandTypePercent:
			return true
		}
	}
	return true
}

func equalDeadbandAbsolute(current, previous ua.Variant, deadband float64) bool {
	if current == nil || previous == nil {
		return current == previous
	}
	vc := reflect.ValueOf(current)
	vp := reflect.ValueOf(previous)
	if vc.Type() != vp.Type() {
		return false
	}
	switch vc.Kind() {
	case reflect.Array:
		for i := 0; i < vc.Len(); i++ {
			if !equalDeadbandAbsolute(vc.Index(i), vp.Index(i), deadband) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if vc.IsNil() != vp.IsNil() {
			return false
		}
		if vc.Len() != vp.Len() {
			return false
		}
		if vc.UnsafePointer() == vp.UnsafePointer() {
			return true
		}
		// special case for []byte, which is common.
		if vc.Type().Elem().Kind() == reflect.Uint8 {
			return bytes.Equal(vc.Bytes(), vp.Bytes())
		}
		for i := 0; i < vc.Len(); i++ {
			if !equalDeadbandAbsolute(vc.Index(i), vp.Index(i), deadband) {
				return false
			}
		}
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return math.Abs(float64(vc.Int()-vp.Int())) <= deadband
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return math.Abs(float64(vc.Uint()-vp.Uint())) <= deadband
	case reflect.Float32, reflect.Float64:
		return math.Abs(vc.Float()-vp.Float()) <= deadband
	}
	return false
}

// withTimestamps returns a new instance of DataValue with only the selected timestamps.
func withTimestamps(value ua.DataValue, timestampsToReturn ua.TimestampsToReturn) ua.DataValue {
	switch timestampsToReturn {
	case ua.TimestampsToReturnSource:
		return ua.NewDataValue(value.Value, value.StatusCode, value.SourceTimestamp, 0, time.Time{}, 0)
	case ua.TimestampsToReturnServer:
		return ua.NewDataValue(value.Value, value.StatusCode, time.Time{}, 0, value.ServerTimestamp, 0)
	case ua.TimestampsToReturnNeither:
		return ua.NewDataValue(value.Value, value.StatusCode, time.Time{}, 0, time.Time{}, 0)
	default:
		return value
	}
}
