// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"math"
	"reflect"
	"sync/atomic"
	"time"

	"sync"

	"github.com/awcullen/opcua/ua"
	deque "github.com/gammazero/deque"
)

const (
	maxQueueSize        = 1024
	maxSamplingInterval = 60 * 1000.0
)

var (
	monitoredItemID = uint32(0)
)

// MonitoredItem specifies the node that is monitored for data changes or events.
type MonitoredItem struct {
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
	queue               deque.Deque
	node                Node
	dataChangeFilter    ua.DataChangeFilter
	eventFilter         ua.EventFilter
	previousQueuedValue ua.DataValue
	sub                 *Subscription
	srv                 *Server
	prequeue            deque.Deque
	ts                  time.Time
	ti                  time.Duration
	cachedCtx           context.Context
	triggeredItems      []*MonitoredItem
	triggered           bool
}

// NewMonitoredItem constructs a new MonitoredItem.
func NewMonitoredItem(ctx context.Context, sub *Subscription, node Node, itemToMonitor ua.ReadValueID, monitoringMode ua.MonitoringMode, parameters ua.MonitoringParameters, timestampsToReturn ua.TimestampsToReturn, minSamplingInterval float64) *MonitoredItem {
	mi := &MonitoredItem{
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
		queue:               deque.Deque{},
		prequeue:            deque.Deque{},
		previousQueuedValue: ua.NewDataValue(nil, ua.BadWaitingForInitialData, time.Time{}, 0, time.Time{}, 0),
	}
	mi.setQueueSize(parameters.QueueSize)
	mi.setSamplingInterval(parameters.SamplingInterval)
	mi.setFilter(parameters.Filter)
	mi.Lock()
	mi.startMonitoring(ctx)
	mi.Unlock()
	return mi
}

// Modify modifies the MonitoredItem.
func (mi *MonitoredItem) Modify(ctx context.Context, req ua.MonitoredItemModifyRequest) ua.MonitoredItemModifyResult {
	mi.Lock()
	defer mi.Unlock()
	mi.stopMonitoring()
	mi.clientHandle = req.RequestedParameters.ClientHandle
	mi.discardOldest = req.RequestedParameters.DiscardOldest
	mi.setQueueSize(req.RequestedParameters.QueueSize)
	mi.setSamplingInterval(req.RequestedParameters.SamplingInterval)
	mi.setFilter(req.RequestedParameters.Filter)
	mi.startMonitoring(ctx)
	return ua.MonitoredItemModifyResult{RevisedSamplingInterval: mi.samplingInterval, RevisedQueueSize: mi.queueSize}
}

// Delete deletes the MonitoredItem.
func (mi *MonitoredItem) Delete() {
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
func (mi *MonitoredItem) SetMonitoringMode(ctx context.Context, mode ua.MonitoringMode) {
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
	mi.startMonitoring(ctx)
}

func (mi *MonitoredItem) setQueueSize(queueSize uint32) {
	switch mi.itemToMonitor.AttributeID {
	case ua.AttributeIDEventNotifier:
		queueSize = maxQueueSize
	default:
		if queueSize > maxQueueSize {
			queueSize = maxQueueSize
		}
		if queueSize < 1 {
			queueSize = 1
		}
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
			if v, ok := mi.queue.Front().(ua.DataValue); ok {
				v.StatusCode = ua.StatusCode(uint32(v.StatusCode) | ua.InfoTypeDataValue | ua.Overflow)
			}
		}
	} else {
		for mi.queue.Len() > int(mi.queueSize) {
			mi.queue.PopBack()
			overflow = true
		}
		if overflow && mi.queue.Len() > 1 {
			// set overflow bit of statuscode
			if v, ok := mi.queue.Back().(ua.DataValue); ok {
				v.StatusCode = ua.StatusCode(uint32(v.StatusCode) | ua.InfoTypeDataValue | ua.Overflow)
			}
		}
	}
}

// SamplingInterval returns the sampling interval in ms of the MonitoredItem.
func (mi *MonitoredItem) SamplingInterval() float64 {
	mi.RLock()
	defer mi.RUnlock()
	return mi.samplingInterval
}

func (mi *MonitoredItem) setSamplingInterval(samplingInterval float64) {
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
	case ua.AttributeIDEventNotifier:
		samplingInterval = 0
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

func (mi *MonitoredItem) setFilter(filter interface{}) {
	mi.dataChangeFilter = ua.DataChangeFilter{Trigger: ua.DataChangeTriggerStatusValue}
	mi.eventFilter = ua.EventFilter{}
	switch mi.itemToMonitor.AttributeID {
	case ua.AttributeIDValue:
		if dcf, ok := filter.(ua.DataChangeFilter); ok {
			mi.dataChangeFilter = dcf
		}
	case ua.AttributeIDEventNotifier:
		if ef, ok := filter.(ua.EventFilter); ok {
			mi.eventFilter = ef
		}
	}
}

func (mi *MonitoredItem) startMonitoring(ctx context.Context) {
	mi.cachedCtx = ctx
	mi.ts = time.Now()
	if mi.monitoringMode == ua.MonitoringModeDisabled {
		return
	}

	switch mi.itemToMonitor.AttributeID {
	case ua.AttributeIDEventNotifier:

	default:
		v := mi.srv.readValue(ctx, mi.itemToMonitor)
		mi.prequeue.PushBack(v)
		mi.Unlock()
		mi.srv.Scheduler().GetPollGroup(time.Duration(mi.samplingInterval) * time.Millisecond).Subscribe(mi)
		mi.Lock()
	}
}

func (mi *MonitoredItem) stopMonitoring() {
	switch mi.itemToMonitor.AttributeID {
	case ua.AttributeIDEventNotifier:

	default:
		mi.Unlock()
		mi.srv.Scheduler().GetPollGroup(time.Duration(mi.samplingInterval) * time.Millisecond).Unsubscribe(mi)
		mi.Lock()
	}
	mi.cachedCtx = nil
}

// Poll reads the value of the itemToMonitor.
func (mi *MonitoredItem) Poll() {
	mi.Lock()
	if n := mi.node; n != nil {
		v := mi.srv.readValue(mi.cachedCtx, mi.itemToMonitor)
		mi.prequeue.PushBack(v)
	}
	mi.Unlock()
}

// AddTriggeredItem adds a item to be triggered by this item.
func (mi *MonitoredItem) AddTriggeredItem(item *MonitoredItem) bool {
	mi.Lock()
	mi.triggeredItems = append(mi.triggeredItems, item)
	mi.Unlock()
	return true
}

// RemoveTriggeredItem removes an item to be triggered by this item.
func (mi *MonitoredItem) RemoveTriggeredItem(item *MonitoredItem) bool {
	mi.Lock()
	ret := false
	for i, e := range mi.triggeredItems {
		if e.id == item.id {
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

func (mi *MonitoredItem) enqueue(item interface{}) {
	overflow := false
	if mi.discardOldest {
		for mi.queue.Len() >= int(mi.queueSize) {
			mi.queue.PopFront() // discard oldest
			overflow = true
		}
		mi.queue.PushBack(item)
		if overflow && mi.queueSize > 1 {
			// set overflow bit of statuscode
			if v, ok := mi.queue.Front().(ua.DataValue); ok {
				v.StatusCode = ua.StatusCode(uint32(v.StatusCode) | ua.InfoTypeDataValue | ua.Overflow)
			}
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
			if v, ok := mi.queue.Back().(ua.DataValue); ok {
				v.StatusCode = ua.StatusCode(uint32(v.StatusCode) | ua.InfoTypeDataValue | ua.Overflow)
			}
			mi.sub.monitoringQueueOverflowCount++
		}
	}
}

func (mi *MonitoredItem) notifications(max int) (notifications []interface{}, more bool) {
	mi.Lock()
	defer mi.Unlock()
	notifications = make([]interface{}, 0, 4)
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

func (mi *MonitoredItem) notificationsAvailable(tn time.Time, late bool, resend bool) bool {
	_ = late
	mi.Lock()
	defer mi.Unlock()
	// if disabled, then report false.
	if mi.monitoringMode == ua.MonitoringModeDisabled {
		mi.ts = tn
		return false
	}
	// update queue and report if queue has notifications available.
	switch mi.itemToMonitor.AttributeID {
	case ua.AttributeIDEventNotifier:
		// TODO: implement event queue
	default:
		// if in sampling interval mode, queue the last value of each sampling interval
		if mi.ti > 0 {
			// log.Printf("Sample from %s to %s", mi.ts.Add(-mi.ti).Format(time.StampMilli), tn.Format(time.StampMilli))
			v := mi.previousQueuedValue
			// for each interval
			for ; !mi.ts.After(tn); mi.ts = mi.ts.Add(mi.ti) {
				// for each value in prequeue
				for mi.prequeue.Len() > 0 {
					// peek
					peek := mi.prequeue.Front().(ua.DataValue)
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
					if mi.triggeredItems != nil {
						for _, item := range mi.triggeredItems {
							item.triggered = true
							// log.Printf("Item %d triggered %d", mi.id, item.id)
						}
					}
				}
			}
		} else {
			// for each value in prequeue
			for mi.prequeue.Len() > 0 {
				v := mi.prequeue.PopFront().(ua.DataValue)
				if mi.isDataChange(v, mi.previousQueuedValue) {
					mi.enqueue(withTimestamps(v, mi.timestampsToReturn))
					mi.previousQueuedValue = v
					if mi.triggeredItems != nil {
						for _, item := range mi.triggeredItems {
							item.triggered = true
							// log.Printf("Item %d triggered %d", mi.id, item.id)
						}
					}
				}
			}
		}
		if resend && mi.monitoringMode == ua.MonitoringModeReporting {
			if mi.queue.Len() == 0 {
				v := mi.srv.readValue(mi.cachedCtx, mi.itemToMonitor)
				mi.enqueue(withTimestamps(v, mi.timestampsToReturn))
				mi.previousQueuedValue = v
			}
		}
	}
	return mi.queue.Len() > 0 && (mi.monitoringMode == ua.MonitoringModeReporting || mi.triggered)
}

func (mi *MonitoredItem) isDataChange(current, previous ua.DataValue) bool {
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
	switch c := current.(type) {
	case nil:
		return previous == nil
	case int8:
		if p, ok := previous.(int8); ok {
			return math.Abs(float64(c)-float64(p)) <= deadband
		}
	case uint8:
		if p, ok := previous.(uint8); ok {
			return math.Abs(float64(c)-float64(p)) <= deadband
		}
	case int16:
		if p, ok := previous.(int16); ok {
			return math.Abs(float64(c)-float64(p)) <= deadband
		}
	case uint16:
		if p, ok := previous.(uint16); ok {
			return math.Abs(float64(c)-float64(p)) <= deadband
		}
	case int32:
		if p, ok := previous.(int32); ok {
			return math.Abs(float64(c)-float64(p)) <= deadband
		}
	case uint32:
		if p, ok := previous.(uint32); ok {
			return math.Abs(float64(c)-float64(p)) <= deadband
		}
	case int64:
		if p, ok := previous.(int64); ok {
			return math.Abs(float64(c)-float64(p)) <= deadband
		}
	case uint64:
		if p, ok := previous.(uint64); ok {
			return math.Abs(float64(c)-float64(p)) <= deadband
		}
	case float32:
		if p, ok := previous.(float32); ok {
			return math.Abs(float64(c)-float64(p)) <= deadband
		}
	case float64:
		if p, ok := previous.(float64); ok {
			return math.Abs(float64(c)-float64(p)) <= deadband
		}
	case []int8:
		if p, ok := previous.([]int8); ok {
			for i := 0; i < len(c); i++ {
				if math.Abs(float64(c[i])-float64(p[i])) > deadband {
					return false
				}
			}
			return true
		}
	case []uint8:
		if p, ok := previous.([]uint8); ok {
			for i := 0; i < len(c); i++ {
				if math.Abs(float64(c[i])-float64(p[i])) > deadband {
					return false
				}
			}
			return true
		}
	case []int16:
		if p, ok := previous.([]int16); ok {
			for i := 0; i < len(c); i++ {
				if math.Abs(float64(c[i])-float64(p[i])) > deadband {
					return false
				}
			}
			return true
		}
	case []uint16:
		if p, ok := previous.([]uint16); ok {
			for i := 0; i < len(c); i++ {
				if math.Abs(float64(c[i])-float64(p[i])) > deadband {
					return false
				}
			}
			return true
		}
	case []int32:
		if p, ok := previous.([]int32); ok {
			for i := 0; i < len(c); i++ {
				if math.Abs(float64(c[i])-float64(p[i])) > deadband {
					return false
				}
			}
			return true
		}
	case []uint32:
		if p, ok := previous.([]uint32); ok {
			for i := 0; i < len(c); i++ {
				if math.Abs(float64(c[i])-float64(p[i])) > deadband {
					return false
				}
			}
			return true
		}
	case []int64:
		if p, ok := previous.([]int64); ok {
			for i := 0; i < len(c); i++ {
				if math.Abs(float64(c[i])-float64(p[i])) > deadband {
					return false
				}
			}
			return true
		}
	case []uint64:
		if p, ok := previous.([]uint64); ok {
			for i := 0; i < len(c); i++ {
				if math.Abs(float64(c[i])-float64(p[i])) > deadband {
					return false
				}
			}
			return true
		}
	case []float32:
		if p, ok := previous.([]float32); ok {
			for i := 0; i < len(c); i++ {
				if math.Abs(float64(c[i])-float64(p[i])) > deadband {
					return false
				}
			}
			return true
		}
	case []float64:
		if p, ok := previous.([]float64); ok {
			for i := 0; i < len(c); i++ {
				if math.Abs(float64(c[i])-float64(p[i])) > deadband {
					return false
				}
			}
			return true
		}
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
