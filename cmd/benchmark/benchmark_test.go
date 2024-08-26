// Copyright 2024 Converter Systems LLC. All rights reserved.

package main

import (
	"testing"
	"time"

	awcullen "github.com/awcullen/opcua/ua"
	gopcua "github.com/gopcua/opcua/ua"
)

func BenchmarkGopcuaEncode(b *testing.B) {
	pr := &gopcua.PublishResponse{
		ResponseHeader: &gopcua.ResponseHeader{
			Timestamp:          time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC),
			RequestHandle:      1000085,
			ServiceDiagnostics: &gopcua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   gopcua.NewExtensionObject(nil),
		},
		SubscriptionID:           1296242973,
		AvailableSequenceNumbers: []uint32{4},
		MoreNotifications:        false,
		NotificationMessage: &gopcua.NotificationMessage{
			SequenceNumber: 4,
			PublishTime:    time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC),
			NotificationData: []*gopcua.ExtensionObject{
				gopcua.NewExtensionObject(&gopcua.DataChangeNotification{
					MonitoredItems: []*gopcua.MonitoredItemNotification{
						{
							ClientHandle: 9,
							Value:        &gopcua.DataValue{EncodingMask: 0x15, Value: gopcua.MustVariant(time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC)), Status: 0, SourceTimestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), SourcePicoseconds: 0, ServerTimestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), ServerPicoseconds: 0},
						},
					},
					DiagnosticInfos: []*gopcua.DiagnosticInfo{},
				}),
			},
		},
		Results:         []gopcua.StatusCode{0},
		DiagnosticInfos: []*gopcua.DiagnosticInfo{},
	}
	conn := &MockWriter{}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		body, err := gopcua.Encode(pr)
		if err != nil {
			b.Fatal(err)
		}
		_, err = conn.Write(body)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAwcullenEncode(b *testing.B) {
	pr := &awcullen.PublishResponse{
		ResponseHeader: awcullen.ResponseHeader{
			Timestamp:     time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC),
			RequestHandle: 1000085,
		},
		SubscriptionID:           1296242973,
		AvailableSequenceNumbers: []uint32{4},
		MoreNotifications:        false,
		NotificationMessage: awcullen.NotificationMessage{
			SequenceNumber: 4,
			PublishTime:    time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC),
			NotificationData: []awcullen.ExtensionObject{
				awcullen.DataChangeNotification{
					MonitoredItems: []awcullen.MonitoredItemNotification{
						{
							ClientHandle: 9,
							Value:        awcullen.DataValue{Value: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), StatusCode: 0, SourceTimestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), SourcePicoseconds: 0, ServerTimestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), ServerPicoseconds: 0},
						},
					},
					DiagnosticInfos: []awcullen.DiagnosticInfo{},
				},
			},
		},
		Results:         []awcullen.StatusCode{0},
		DiagnosticInfos: []awcullen.DiagnosticInfo{},
	}
	ec := awcullen.NewEncodingContext()
	conn := &MockWriter{}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		enc := awcullen.NewBinaryEncoder(conn, ec)
		if err := enc.Encode(pr); err != nil {
			b.Fatal(err)
		}
	}
}

type MockWriter struct {
}

func (w *MockWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}
