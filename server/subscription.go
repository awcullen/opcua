package server

import (
	"container/list"
	"context"
	"log"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awcullen/opcua/ua"
	"github.com/google/uuid"
)

const (
	minPublishingInterval        = 125.0
	maxPublishingInterval        = 60 * 1000.0
	minLifetime                  = 10 * 1000.0
	maxLifetime                  = 60 * 60 * 1000.0
	maxRetransmissionQueueLength = 128
)

var (
	subscriptionID = uint32(0)
)

// Subscription organizes MonitoredItems.
type Subscription struct {
	sync.RWMutex
	id                           uint32
	publishingInterval           float64
	lifetimeCount                uint32
	maxKeepAliveCount            uint32
	maxNotificationsPerPublish   uint32
	publishingEnabled            bool
	priority                     byte
	seqNum                       uint32
	cancelPublishing             chan struct{}
	items                        map[uint32]*MonitoredItem
	keepAliveCounter             uint32
	lifetimeCounter              uint32
	moreNotifications            bool
	session                      *Session
	manager                      *SubscriptionManager
	retransmissionQueue          *list.List
	isLate                       bool
	resend                       bool
	diagnosticsNodeId            ua.NodeID
	sessionId                    ua.NodeID
	modifyCount                  uint32
	republishRequestCount        uint32
	republishMessageRequestCount uint32
	republishMessageCount        uint32
	publishRequestCount          uint32
	notificationsCount           uint32
	dataChangeNotificationsCount uint32
	eventNotificationsCount      uint32
	unacknowledgedMessageCount   uint32
	latePublishRequestCount      uint32
	monitoredItemCount           uint32
	disabledMonitoredItemCount   uint32
	monitoringQueueOverflowCount uint32
}

// NewSubscription instantiates a new Subscription.
func NewSubscription(manager *SubscriptionManager, session *Session, publishingInterval float64, lifetimeCount uint32, maxKeepAliveCount uint32, maxNotificationsPerPublish uint32, publishingEnabled bool, priority byte) *Subscription {
	s := &Subscription{
		manager:             manager,
		session:             session,
		id:                  atomic.AddUint32(&subscriptionID, 1),
		publishingEnabled:   publishingEnabled,
		priority:            priority,
		seqNum:              1,
		keepAliveCounter:    math.MaxUint32,
		items:               make(map[uint32]*MonitoredItem),
		retransmissionQueue: list.New(),
		diagnosticsNodeId:   ua.NewNodeIDGUID(1, uuid.New()),
		sessionId:           session.sessionId,
	}
	s.setPublishingInterval(publishingInterval)
	s.setMaxKeepAliveCount(maxKeepAliveCount)
	s.setLifetimeCount(lifetimeCount)
	s.setMaxNotificationsPerPublish(maxNotificationsPerPublish)
	// s.startPublishing()
	return s
}

func (s *Subscription) IsExpired() bool {
	s.RLock()
	ret := s.lifetimeCounter >= s.lifetimeCount
	s.RUnlock()
	return ret
}

func (s *Subscription) Delete() {
	s.Lock()
	s.deleteImpl()
	s.Unlock()
}

func (s *Subscription) deleteImpl() {
	s.stopPublishing()
	for id, item := range s.items {
		delete(s.items, id)
		item.Delete()
	}
	s.items = nil
	q := s.retransmissionQueue
	// log.Printf("Empty retransmissionQueue len: %d\n", q.Len())
	for e := q.Front(); e != nil; e = e.Next() {
		q.Remove(e)
		e.Value = nil
	}
	s.retransmissionQueue = nil
	s.session = nil
	s.manager = nil
}

func (s *Subscription) Items() []*MonitoredItem {
	s.RLock()
	ret := []*MonitoredItem{}
	for _, v := range s.items {
		ret = append(ret, v)
	}
	s.RUnlock()
	return ret
}

func (s *Subscription) FindItem(id uint32) (*MonitoredItem, bool) {
	s.RLock()
	item, ok := s.items[id]
	s.RUnlock()
	return item, ok
}

func (s *Subscription) AppendItem(item *MonitoredItem) bool {
	s.Lock()
	ret := false
	if _, ok := s.items[item.id]; !ok {
		s.items[item.id] = item
		s.monitoredItemCount++
		if item.monitoringMode == ua.MonitoringModeDisabled {
			s.disabledMonitoredItemCount++
		}
		ret = true
	}
	s.Unlock()
	return ret
}

func (s *Subscription) DeleteItem(ctx context.Context, id uint32) bool {
	s.Lock()
	ret := false
	if item, ok := s.items[id]; ok {
		delete(s.items, id)
		item.Delete()
		s.monitoredItemCount--
		if item.monitoringMode == ua.MonitoringModeDisabled {
			s.disabledMonitoredItemCount--
		}
		ret = true
	}
	s.Unlock()
	return ret
}

func (s *Subscription) SetPublishingMode(publishingEnabled bool) {
	s.Lock()
	s.publishingEnabled = publishingEnabled
	s.lifetimeCounter = 0
	s.Unlock()
}

func (s *Subscription) Modify(publishingInterval float64, lifetimeCount uint32, maxKeepAliveCount uint32, maxNotificationsPerPublish uint32, priority byte) {
	s.Lock()
	s.stopPublishing()
	s.setPublishingInterval(publishingInterval)
	s.setMaxKeepAliveCount(maxKeepAliveCount)
	s.setLifetimeCount(lifetimeCount)
	s.setMaxNotificationsPerPublish(maxNotificationsPerPublish)
	s.priority = priority
	s.lifetimeCounter = 0
	s.modifyCount++
	s.startPublishing()
	s.Unlock()
}

func (s *Subscription) setPublishingInterval(publishingInterval float64) {
	if math.IsNaN(publishingInterval) {
		publishingInterval = minPublishingInterval
	}
	if publishingInterval < minPublishingInterval {
		publishingInterval = minPublishingInterval
	}
	if publishingInterval > maxPublishingInterval {
		publishingInterval = maxPublishingInterval
	}
	s.publishingInterval = publishingInterval
}

func (s *Subscription) setMaxKeepAliveCount(maxKeepAliveCount uint32) {
	if maxKeepAliveCount == 0 {
		maxKeepAliveCount = 3
	}
	keepAliveInterval := float64(maxKeepAliveCount) * s.publishingInterval
	// keep alive interval cannot be longer than the max subscription lifetime.
	if keepAliveInterval > maxLifetime {
		maxKeepAliveCount = uint32(maxLifetime / s.publishingInterval)
		if maxKeepAliveCount < math.MaxUint32 {
			if math.Mod(maxLifetime, s.publishingInterval) != 0 {
				maxKeepAliveCount++
			}
		}
		keepAliveInterval = float64(maxKeepAliveCount) * s.publishingInterval
	}
	// the time between publishes cannot exceed the max publishing interval.
	if keepAliveInterval > maxPublishingInterval {
		maxKeepAliveCount = uint32(maxPublishingInterval / s.publishingInterval)
		if maxKeepAliveCount < math.MaxUint32 {
			if math.Mod(maxPublishingInterval, s.publishingInterval) != 0 {
				maxKeepAliveCount++
			}
		}
	}
	s.maxKeepAliveCount = maxKeepAliveCount
}

func (s *Subscription) setLifetimeCount(lifetimeCount uint32) {
	lifetimeInterval := float64(lifetimeCount) * s.publishingInterval
	// lifetime cannot be longer than the max subscription lifetime.
	if lifetimeInterval > maxLifetime {
		lifetimeCount = uint32(maxLifetime / s.publishingInterval)
		if lifetimeCount < math.MaxUint32 {
			if math.Mod(maxLifetime, s.publishingInterval) != 0 {
				lifetimeCount++
			}
		}
	}
	// the lifetime must be greater than the keepalive.
	if s.maxKeepAliveCount < math.MaxUint32/3 {
		if s.maxKeepAliveCount*3 > lifetimeCount {
			lifetimeCount = s.maxKeepAliveCount * 3
		}
		lifetimeInterval = float64(lifetimeCount) * s.publishingInterval
	} else {
		lifetimeCount = math.MaxUint32
		lifetimeInterval = math.MaxFloat64
	}
	// apply the minimum.
	if minLifetime > s.publishingInterval && minLifetime > lifetimeInterval {
		lifetimeCount = uint32(minLifetime / s.publishingInterval)

		if lifetimeCount < math.MaxUint32 {
			if math.Mod(minLifetime, s.publishingInterval) != 0 {
				lifetimeCount++
			}
		}
	}
	s.lifetimeCount = lifetimeCount
}

func (s *Subscription) setMaxNotificationsPerPublish(maxNotificationsPerPublish uint32) {
	if maxNotificationsPerPublish > 0 {
		s.maxNotificationsPerPublish = maxNotificationsPerPublish
		return
	}
	s.maxNotificationsPerPublish = math.MaxInt32
}

func (s *Subscription) acknowledge(seqNum uint32) bool {
	s.Lock()
	defer s.Unlock()
	q := s.retransmissionQueue
	for e := q.Front(); e != nil; e = e.Next() {
		if nm, ok := e.Value.(ua.NotificationMessage); ok && nm.SequenceNumber == seqNum {
			q.Remove(e)
			e.Value = nil
			return true
		}
	}
	return false
}

func (s *Subscription) startPublishing() {
	// log.Printf("startPublishing %d \n", s.id)
	s.cancelPublishing = make(chan struct{})

	go func(done chan struct{}, interval time.Duration, f func(time.Time)) {
		ticker := time.NewTicker(interval)
		for {
			select {
			case <-done:
				ticker.Stop()
				return
			case t := <-ticker.C:
				f(t.UTC())
			}
		}
	}(s.cancelPublishing, time.Duration(int64(s.publishingInterval))*time.Millisecond, s.publish)
}

func (s *Subscription) stopPublishing() {
	// log.Printf("stopPublishing %d \n", s.id)
	close(s.cancelPublishing)
}

func (s *Subscription) publish(_ time.Time) {
	// log.Printf("onPublish %d \n", s.id)
	s.Lock()
	notificationsAvailable := false
	tn := time.Now()
	for _, item := range s.items {
		if item.notificationsAvailable(tn, false, s.resend) {
			notificationsAvailable = true
		}
	}
	s.resend = false
	switch {
	case notificationsAvailable && s.publishingEnabled:
		sess := s.session
		if sess == nil {
			log.Printf("Subscription '%d' session in nil.\n", s.id)
			s.Unlock()
			return
		}
		if ch, requestid, req, results, ok := sess.removePublishRequest(); ok {
			more := false
			maxN := int(s.maxNotificationsPerPublish)
			mins := make([]ua.MonitoredItemNotification, 0, 4)
			efls := make([]ua.EventFieldList, 0, 4)
			for _, item := range s.items {
				if item.monitoringMode != ua.MonitoringModeReporting && !item.triggered {
					continue
				}
				// if item.triggered {
				// log.Printf("TriggeredItem %d published.", item.id)
				// }
				if item.itemToMonitor.AttributeID == ua.AttributeIDEventNotifier {
					encs, more1 := item.notifications(maxN)
					for _, enc := range encs {
						if efs, ok := enc.([]ua.Variant); ok {
							efls = append(efls, ua.EventFieldList{ClientHandle: item.clientHandle, EventFields: efs})
							s.eventNotificationsCount++
							s.notificationsCount++
						}
					}
					more = more || more1
					maxN = maxN - len(encs)
				} else {
					encs, more1 := item.notifications(maxN)
					for _, enc := range encs {
						if dv, ok := enc.(ua.DataValue); ok {
							mins = append(mins, ua.MonitoredItemNotification{ClientHandle: item.clientHandle, Value: dv})
							s.dataChangeNotificationsCount++
							s.notificationsCount++
						}
					}
					more = more || more1
					maxN = maxN - len(encs)
				}
			}
			nd := make([]ua.ExtensionObject, 0, 2)
			if len(mins) > 0 {
				nd = append(nd, ua.DataChangeNotification{MonitoredItems: mins})
			}
			if len(efls) > 0 {
				nd = append(nd, ua.EventNotificationList{Events: efls})
			}
			nm := ua.NotificationMessage{
				SequenceNumber:   s.seqNum,
				PublishTime:      tn,
				NotificationData: nd,
			}
			q := s.retransmissionQueue
			for e := q.Front(); e != nil && q.Len() >= maxRetransmissionQueueLength; e = e.Next() {
				q.Remove(e)
				e.Value = nil
			}
			q.PushBack(nm)
			avail := make([]uint32, 0, 4)
			for e := q.Front(); e != nil; e = e.Next() {
				if nm, ok := e.Value.(ua.NotificationMessage); ok {
					avail = append(avail, nm.SequenceNumber)
				}
			}
			ch.Write(
				&ua.PublishResponse{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHeader.RequestHandle,
					},
					SubscriptionID:           s.id,
					AvailableSequenceNumbers: avail,
					MoreNotifications:        more,
					NotificationMessage:      nm,
					Results:                  results,
					DiagnosticInfos:          nil,
				},
				requestid,
			)
			s.unacknowledgedMessageCount = uint32(len(avail))
			s.publishRequestCount++
			if s.seqNum != math.MaxUint32 {
				s.seqNum++
			} else {
				s.seqNum = 1
			}
			s.keepAliveCounter = 0
			s.lifetimeCounter = 0
			s.isLate = false
			s.moreNotifications = more
			s.Unlock()
			return
		}
		// only get here if no publishRequests are queued.
		s.isLate = true
		s.lifetimeCounter++
		if s.lifetimeCounter == s.lifetimeCount {
			// log.Printf("Subscription '%d' expired.\n", s.id)
			nm := ua.NotificationMessage{
				SequenceNumber:   s.seqNum,
				PublishTime:      time.Now(),
				NotificationData: []ua.ExtensionObject{ua.StatusChangeNotification{Status: ua.BadTimeout}},
			}
			s.session.stateChanges <- &stateChangeOp{subscriptionId: s.id, message: nm}
			if s.seqNum != math.MaxUint32 {
				s.seqNum++
			} else {
				s.seqNum = 1
			}
			s.manager.Delete(s)
			s.deleteImpl()
		}
		s.Unlock()
		return

	case s.keepAliveCounter >= s.maxKeepAliveCount:
		sess := s.session
		if sess == nil {
			log.Printf("Subscription '%d' session in nil.\n", s.id)
			s.Unlock()
			return
		}
		if ch, requestid, req, results, ok := sess.removePublishRequest(); ok {
			avail := make([]uint32, 0, 4)
			q := s.retransmissionQueue
			for e := q.Front(); e != nil; e = e.Next() {
				if nm, ok := e.Value.(ua.NotificationMessage); ok {
					avail = append(avail, nm.SequenceNumber)
				}
			}
			ch.Write(
				&ua.PublishResponse{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHeader.RequestHandle,
					},
					SubscriptionID:           s.id,
					AvailableSequenceNumbers: avail,
					MoreNotifications:        false,
					NotificationMessage: ua.NotificationMessage{
						SequenceNumber:   s.seqNum,
						PublishTime:      time.Now(),
						NotificationData: nil,
					},
					Results:         results,
					DiagnosticInfos: nil,
				},
				requestid,
			)
			s.unacknowledgedMessageCount = uint32(len(avail))
			s.publishRequestCount++
			s.keepAliveCounter = 0
			s.lifetimeCounter = 0
			s.isLate = false
			s.Unlock()
			return
		}
		// only get here if no publishRequests are queued.
		s.isLate = true
		s.lifetimeCounter++
		if s.lifetimeCounter == s.lifetimeCount {
			// log.Printf("Subscription '%d' expired.\n", s.id)
			nm := ua.NotificationMessage{
				SequenceNumber:   s.seqNum,
				PublishTime:      time.Now(),
				NotificationData: []ua.ExtensionObject{ua.StatusChangeNotification{Status: ua.BadTimeout}},
			}
			s.session.stateChanges <- &stateChangeOp{subscriptionId: s.id, message: nm}
			if s.seqNum != math.MaxUint32 {
				s.seqNum++
			} else {
				s.seqNum = 1
			}
			s.manager.Delete(s)
			s.deleteImpl()
		}
		s.Unlock()
		return

	default:
		s.keepAliveCounter++
		s.Unlock()
		return
	}
}

func (s *Subscription) handleLatePublishRequest(ch *serverSecureChannel, requestid uint32, req *ua.PublishRequest, results []ua.StatusCode) bool {
	s.Lock()
	if !s.isLate {
		s.Unlock()
		return false
	}
	tn := time.Now()
	notificationsAvailable := false
	for _, item := range s.items {
		if item.notificationsAvailable(tn, true, false) {
			notificationsAvailable = true
		}
	}
	switch {
	case notificationsAvailable && s.publishingEnabled:
		// log.Printf("handleLatePublishRequest %d, %d\n", s.id, s.priority)
		more := false
		maxN := int(s.maxNotificationsPerPublish)
		mins := make([]ua.MonitoredItemNotification, 0, 4)
		efls := make([]ua.EventFieldList, 0, 4)
		for _, item := range s.items {
			if item.monitoringMode != ua.MonitoringModeReporting && !item.triggered {
				continue
			}
			// if item.triggered {
			// 	// log.Printf("TriggeredItem %d published late.", item.id)
			// }
			if item.itemToMonitor.AttributeID == ua.AttributeIDEventNotifier {
				encs, more1 := item.notifications(maxN)
				for _, enc := range encs {
					if efs, ok := enc.([]ua.Variant); ok {
						efls = append(efls, ua.EventFieldList{ClientHandle: item.clientHandle, EventFields: efs})
						s.eventNotificationsCount++
						s.notificationsCount++
					}
				}
				more = more || more1
				maxN = maxN - len(encs)
			} else {
				encs, more1 := item.notifications(maxN)
				for _, enc := range encs {
					if dv, ok := enc.(ua.DataValue); ok {
						mins = append(mins, ua.MonitoredItemNotification{ClientHandle: item.clientHandle, Value: dv})
						s.dataChangeNotificationsCount++
						s.notificationsCount++
					}
				}
				more = more || more1
				maxN = maxN - len(encs)
			}
		}
		nd := make([]ua.ExtensionObject, 0, 2)
		if len(mins) > 0 {
			nd = append(nd, ua.DataChangeNotification{MonitoredItems: mins})
		}
		if len(efls) > 0 {
			nd = append(nd, ua.EventNotificationList{Events: efls})
		}
		nm := ua.NotificationMessage{
			SequenceNumber:   s.seqNum,
			PublishTime:      tn,
			NotificationData: nd,
		}
		q := s.retransmissionQueue
		for e := q.Front(); e != nil && q.Len() >= maxRetransmissionQueueLength; e = e.Next() {
			q.Remove(e)
		}
		q.PushBack(nm)
		avail := make([]uint32, 0, 4)
		for e := q.Front(); e != nil; e = e.Next() {
			if nm, ok := e.Value.(ua.NotificationMessage); ok {
				avail = append(avail, nm.SequenceNumber)
			}
		}
		ch.Write(
			&ua.PublishResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
				},
				SubscriptionID:           s.id,
				AvailableSequenceNumbers: avail,
				MoreNotifications:        more,
				NotificationMessage:      nm,
				Results:                  results,
				DiagnosticInfos:          nil,
			},
			requestid,
		)
		s.publishRequestCount++
		s.latePublishRequestCount++
		s.unacknowledgedMessageCount = uint32(len(avail))
		if s.seqNum != math.MaxUint32 {
			s.seqNum++
		} else {
			s.seqNum = 1
		}
		s.keepAliveCounter = 0
		s.lifetimeCounter = 0
		s.moreNotifications = more
		if !more {
			s.isLate = false
		}
		s.Unlock()
		return true
	case s.keepAliveCounter >= s.maxKeepAliveCount:
		avail := make([]uint32, 0, 4)
		q := s.retransmissionQueue
		for e := q.Front(); e != nil; e = e.Next() {
			if nm, ok := e.Value.(ua.NotificationMessage); ok {
				avail = append(avail, nm.SequenceNumber)
			}
		}
		results := make([]ua.StatusCode, len(req.SubscriptionAcknowledgements))
		ch.Write(
			&ua.PublishResponse{
				ResponseHeader: ua.ResponseHeader{
					Timestamp:     time.Now(),
					RequestHandle: req.RequestHeader.RequestHandle,
				},
				SubscriptionID:           s.id,
				AvailableSequenceNumbers: avail,
				MoreNotifications:        false,
				NotificationMessage: ua.NotificationMessage{
					SequenceNumber:   s.seqNum,
					PublishTime:      time.Now(),
					NotificationData: nil,
				},
				Results:         results,
				DiagnosticInfos: nil,
			},
			requestid,
		)
		s.publishRequestCount++
		s.latePublishRequestCount++
		s.unacknowledgedMessageCount = uint32(len(avail))
		s.keepAliveCounter = 0
		s.lifetimeCounter = 0
		s.isLate = false
		s.Unlock()
		return true
	}
	s.Unlock()
	return false
}

func (s *Subscription) resendData() {
	// log.Printf("resendData %d \n", s.id)
	s.Lock()
	s.resend = true
	s.Unlock()
}
