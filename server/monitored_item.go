// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"context"
	"time"

	"github.com/awcullen/opcua/ua"
)

const (
	maxQueueSize        = 1024
	maxSamplingInterval = 60 * 1000.0
)

var (
	monitoredItemID = uint32(0)
)

// MonitoredItem specifies a node that is monitored
type MonitoredItem interface {
	ID() uint32
	Node() Node
	ItemToMonitor() ua.ReadValueID
	SamplingInterval() float64
	QueueSize() uint32
	MonitoringMode() ua.MonitoringMode
	ClientHandle() uint32
	Triggered() bool
	SetTriggered(bool)
	Modify(ctx context.Context, req ua.MonitoredItemModifyRequest) ua.MonitoredItemModifyResult
	Delete()
	SetMonitoringMode(ctx context.Context, mode ua.MonitoringMode)
	notifications(max int) (notifications []interface{}, more bool)
	notificationsAvailable(tn time.Time, late bool, resend bool) bool
	AddTriggeredItem(item MonitoredItem) bool
	RemoveTriggeredItem(item MonitoredItem) bool
}
