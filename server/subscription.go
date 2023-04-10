package server

import (
	"container/list"
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
	maxLifetimeCount             uint32
	maxKeepAliveCount            uint32
	maxNotificationsPerPublish   uint32
	publishingEnabled            bool
	priority                     byte
	nextSequenceNumber           uint32
	cancelPublishing             chan struct{}
	items                        map[uint32]MonitoredItem
	keepAliveCount               uint32
	lifetimeCount                uint32
	moreNotifications            bool
	isLate                       bool
	resend                       bool
	session                      *Session
	manager                      *SubscriptionManager
	retransmissionQueue          *list.List
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
		nextSequenceNumber:  1,
		items:               make(map[uint32]MonitoredItem),
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
	defer s.RUnlock()
	return s.lifetimeCount >= s.maxLifetimeCount
}

func (s *Subscription) Delete() {
	s.Lock()
	defer s.Unlock()
	s.deleteImpl()
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

func (s *Subscription) Items() []MonitoredItem {
	s.RLock()
	defer s.RUnlock()
	ret := []MonitoredItem{}
	for _, v := range s.items {
		ret = append(ret, v)
	}
	return ret
}

func (s *Subscription) FindItem(id uint32) (MonitoredItem, bool) {
	s.RLock()
	defer s.RUnlock()
	item, ok := s.items[id]
	return item, ok
}

func (s *Subscription) AppendItem(item MonitoredItem) bool {
	s.Lock()
	defer s.Unlock()
	ret := false
	if _, ok := s.items[item.ID()]; !ok {
		s.items[item.ID()] = item
		s.monitoredItemCount++
		if item.MonitoringMode() == ua.MonitoringModeDisabled {
			s.disabledMonitoredItemCount++
		}
		ret = true
	}
	return ret
}

func (s *Subscription) DeleteItem(id uint32) bool {
	s.Lock()
	defer s.Unlock()
	ret := false
	if item, ok := s.items[id]; ok {
		delete(s.items, id)
		item.Delete()
		s.monitoredItemCount--
		if item.MonitoringMode() == ua.MonitoringModeDisabled {
			s.disabledMonitoredItemCount--
		}
		ret = true
	}
	return ret
}

func (s *Subscription) SetPublishingMode(publishingEnabled bool) {
	s.Lock()
	defer s.Unlock()
	s.publishingEnabled = publishingEnabled
	s.lifetimeCount = 0
}

func (s *Subscription) Modify(publishingInterval float64, lifetimeCount uint32, maxKeepAliveCount uint32, maxNotificationsPerPublish uint32, priority byte) {
	s.Lock()
	defer s.Unlock()
	s.stopPublishing()
	s.setPublishingInterval(publishingInterval)
	s.setMaxKeepAliveCount(maxKeepAliveCount)
	s.setLifetimeCount(lifetimeCount)
	s.setMaxNotificationsPerPublish(maxNotificationsPerPublish)
	s.priority = priority
	s.lifetimeCount = 0
	s.modifyCount++
	s.startPublishing()
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
	s.maxLifetimeCount = lifetimeCount
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

	go func(done chan struct{}, interval time.Duration, f func(time.Time) error) {
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

func (s *Subscription) publish(tn time.Time) error {
	// log.Printf("onPublish id: %d, keepAlive: %d, lifetime: %d\n", s.id, s.keepAliveCount, s.lifetimeCount)
	s.Lock()
	defer s.Unlock()
	notificationsAvailable := false
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
			return nil
		}
		ch, requestid, req, results, ok, err := sess.removePublishRequest()
		if err != nil {
			return err
		}
		if ok {
			more := false
			maxN := int(s.maxNotificationsPerPublish)
			mins := make([]ua.MonitoredItemNotification, 0, 4)
			efls := make([]ua.EventFieldList, 0, 4)
			for _, item := range s.items {
				if item.MonitoringMode() != ua.MonitoringModeReporting && !item.Triggered() {
					continue
				}
				// if item.triggered {
				// log.Printf("TriggeredItem %d published.", item.id)
				// }
				switch mi := item.(type) {
				case *EventMonitoredItem:
					encs, more1 := mi.notifications(maxN)
					for _, enc := range encs {
						if efs, ok := enc.([]ua.Variant); ok {
							efls = append(efls, ua.EventFieldList{ClientHandle: item.ClientHandle(), EventFields: efs})
							s.eventNotificationsCount++
							s.notificationsCount++
						}
					}
					more = more || more1
					maxN = maxN - len(encs)
				case *DataChangeMonitoredItem:
					encs, more1 := mi.notifications(maxN)
					for _, enc := range encs {
						if dv, ok := enc.(ua.DataValue); ok {
							mins = append(mins, ua.MonitoredItemNotification{ClientHandle: item.ClientHandle(), Value: dv})
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
				SequenceNumber:   s.nextSequenceNumber,
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
			err := ch.Write(
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
			if err != nil {
				return err
			}
			s.unacknowledgedMessageCount = uint32(len(avail))
			s.publishRequestCount++
			s.nextSequenceNumber++
			s.keepAliveCount = 0
			s.lifetimeCount = 0
			s.isLate = false
			s.moreNotifications = more
			return nil
		}
		// only get here if no publishRequests are queued.
		s.isLate = true
		s.lifetimeCount++
		if s.lifetimeCount >= s.maxLifetimeCount {
			// log.Printf("Subscription '%d' expired.\n", s.id)
			nm := ua.NotificationMessage{
				SequenceNumber:   s.nextSequenceNumber,
				PublishTime:      time.Now(),
				NotificationData: []ua.ExtensionObject{ua.StatusChangeNotification{Status: ua.BadTimeout}},
			}
			s.session.stateChanges <- &stateChangeOp{subscriptionId: s.id, message: nm}
			s.nextSequenceNumber++
			s.manager.Delete(s)
			s.deleteImpl()
		}
		return nil

	default:
		s.keepAliveCount++
		if s.keepAliveCount >= s.maxKeepAliveCount || s.publishRequestCount == 0 {
			sess := s.session
			if sess == nil {
				log.Printf("Subscription '%d' session in nil.\n", s.id)
				return nil
			}
			ch, requestid, req, results, ok, err := sess.removePublishRequest()
			if err != nil {
				return err
			}
			if ok {
				avail := make([]uint32, 0, 4)
				q := s.retransmissionQueue
				for e := q.Front(); e != nil; e = e.Next() {
					if nm, ok := e.Value.(ua.NotificationMessage); ok {
						avail = append(avail, nm.SequenceNumber)
					}
				}
				err := ch.Write(
					&ua.PublishResponse{
						ResponseHeader: ua.ResponseHeader{
							Timestamp:     time.Now(),
							RequestHandle: req.RequestHeader.RequestHandle,
						},
						SubscriptionID:           s.id,
						AvailableSequenceNumbers: avail,
						MoreNotifications:        false,
						NotificationMessage: ua.NotificationMessage{
							SequenceNumber:   s.nextSequenceNumber,
							PublishTime:      time.Now(),
							NotificationData: nil,
						},
						Results:         results,
						DiagnosticInfos: nil,
					},
					requestid,
				)
				if err != nil {
					return err
				}
				s.unacknowledgedMessageCount = uint32(len(avail))
				s.publishRequestCount++
				s.keepAliveCount = 0
				s.lifetimeCount = 0
				s.isLate = false
				return nil
			}
			// only get here if no publishRequests are queued.
			s.isLate = true
			s.lifetimeCount++
			if s.lifetimeCount == s.maxLifetimeCount {
				// log.Printf("Subscription '%d' expired.\n", s.id)
				nm := ua.NotificationMessage{
					SequenceNumber:   s.nextSequenceNumber,
					PublishTime:      time.Now(),
					NotificationData: []ua.ExtensionObject{ua.StatusChangeNotification{Status: ua.BadTimeout}},
				}
				s.session.stateChanges <- &stateChangeOp{subscriptionId: s.id, message: nm}
				s.nextSequenceNumber++
				s.manager.Delete(s)
				s.deleteImpl()
			}
			return nil
		}
		return nil
	}
}

func (s *Subscription) handleLatePublishRequest(ch *serverSecureChannel, requestid uint32, req *ua.PublishRequest, results []ua.StatusCode) (bool, error) {
	s.Lock()
	defer s.Unlock()
	if !s.isLate {
		return false, nil
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
			if item.MonitoringMode() != ua.MonitoringModeReporting && !item.Triggered() {
				continue
			}
			// if item.triggered {
			// 	// log.Printf("TriggeredItem %d published late.", item.id)
			// }
			switch mi := item.(type) {
			case *EventMonitoredItem:
				encs, more1 := mi.notifications(maxN)
				for _, enc := range encs {
					if efs, ok := enc.([]ua.Variant); ok {
						efls = append(efls, ua.EventFieldList{ClientHandle: item.ClientHandle(), EventFields: efs})
						s.eventNotificationsCount++
						s.notificationsCount++
					}
				}
				more = more || more1
				maxN = maxN - len(encs)
			case *DataChangeMonitoredItem:
				encs, more1 := mi.notifications(maxN)
				for _, enc := range encs {
					if dv, ok := enc.(ua.DataValue); ok {
						mins = append(mins, ua.MonitoredItemNotification{ClientHandle: item.ClientHandle(), Value: dv})
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
			SequenceNumber:   s.nextSequenceNumber,
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
		err := ch.Write(
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
		if err != nil {
			return true, err
		}
		s.publishRequestCount++
		s.latePublishRequestCount++
		s.unacknowledgedMessageCount = uint32(len(avail))
		s.nextSequenceNumber++
		s.keepAliveCount = 0
		s.lifetimeCount = 0
		s.moreNotifications = more
		if !more {
			s.isLate = false
		}
		return true, nil

	default:
		if s.keepAliveCount >= s.maxKeepAliveCount || s.publishRequestCount == 0 {
			avail := make([]uint32, 0, 4)
			q := s.retransmissionQueue
			for e := q.Front(); e != nil; e = e.Next() {
				if nm, ok := e.Value.(ua.NotificationMessage); ok {
					avail = append(avail, nm.SequenceNumber)
				}
			}
			results := make([]ua.StatusCode, len(req.SubscriptionAcknowledgements))
			err := ch.Write(
				&ua.PublishResponse{
					ResponseHeader: ua.ResponseHeader{
						Timestamp:     time.Now(),
						RequestHandle: req.RequestHeader.RequestHandle,
					},
					SubscriptionID:           s.id,
					AvailableSequenceNumbers: avail,
					MoreNotifications:        false,
					NotificationMessage: ua.NotificationMessage{
						SequenceNumber:   s.nextSequenceNumber,
						PublishTime:      time.Now(),
						NotificationData: nil,
					},
					Results:         results,
					DiagnosticInfos: nil,
				},
				requestid,
			)
			if err != nil {
				return true, err
			}
			s.publishRequestCount++
			s.latePublishRequestCount++
			s.unacknowledgedMessageCount = uint32(len(avail))
			s.keepAliveCount = 0
			s.lifetimeCount = 0
			s.isLate = false
			return true, nil
		}
	}
	return false, nil
}

func (s *Subscription) resendData() {
	// log.Printf("resendData %d \n", s.id)
	s.Lock()
	defer s.Unlock()
	s.resend = true
}
