// Copyright 2024 Converter Systems LLC. All rights reserved.

package main

import (
	"testing"
	"time"

	awcullen "github.com/awcullen/opcua/ua"
	gopcua "github.com/gopcua/opcua/ua"
)

/* 
run file benchmarks, results similar to:
pkg: github.com/awcullen/opcua/cmd/benchmark
cpu: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz
BenchmarkGopcuaEncode
BenchmarkGopcuaEncode-4     	  120178	      9332 ns/op	    2536 B/op	      97 allocs/op
BenchmarkAwcullenEncode
BenchmarkAwcullenEncode-4   	 1728259	       859.3 ns/op	     154 B/op	       4 allocs/op
PASS
 */

// BenchmarkGopcuaEncode encodes typical payload to a mock network connection.
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
							Value:        &gopcua.DataValue{EncodingMask: 0x15, Value: gopcua.MustVariant(3.14159), Status: 0, SourceTimestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), SourcePicoseconds: 0, ServerTimestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), ServerPicoseconds: 0},
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

// BenchmarkAwcullenEncode encodes typical payload to a mock network connection.
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
							Value:        awcullen.DataValue{Value: 3.14159, StatusCode: 0, SourceTimestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), SourcePicoseconds: 0, ServerTimestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), ServerPicoseconds: 0},
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
