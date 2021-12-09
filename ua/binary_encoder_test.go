// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
	"github.com/google/uuid"
	"gotest.tools/assert"
)

func TestBoolean(t *testing.T) {
	cases := []struct {
		in    bool
		bytes []byte
	}{
		{
			true,
			[]byte{
				0x01,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteBoolean(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out bool
		if err := dec.ReadBoolean(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestInt32(t *testing.T) {
	cases := []struct {
		in    int32
		bytes []byte
	}{
		{
			1_000_000_000,
			[]byte{
				0x00, 0xCA, 0x9A, 0x3B,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteInt32(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out int32
		if err := dec.ReadInt32(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestFloat(t *testing.T) {
	cases := []struct {
		in    float32
		bytes []byte
	}{
		{
			-6.5,
			[]byte{
				0x00, 0x00, 0xD0, 0xC0,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteFloat(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out float32
		if err := dec.ReadFloat(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestString(t *testing.T) {
	cases := []struct {
		in    string
		bytes []byte
	}{
		{
			"水Boy",
			[]byte{
				0x06, 0x00, 0x00, 0x00, 0xE6, 0xB0, 0xB4, 0x42, 0x6F, 0x79,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteString(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out string
		if err := dec.ReadString(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestTime(t *testing.T) {
	cases := []struct {
		in    time.Time
		bytes []byte
	}{
		{
			time.Date(2020, time.July, 04, 12, 0, 0, 0, time.UTC),
			[]byte{
				0x00, 0xa0, 0xa5, 0xa4, 0xfa, 0x51, 0xd6, 0x01,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteDateTime(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out time.Time
		if err := dec.ReadDateTime(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestGUID(t *testing.T) {
	cases := []struct {
		in    uuid.UUID
		bytes []byte
	}{
		{
			uuid.MustParse("72962B91-FA75-4AE6-8D28-B404DC7DAF63"),
			[]byte{
				// data1 (inverse order)
				0x91, 0x2b, 0x96, 0x72,
				// data2 (inverse order)
				0x75, 0xfa,
				// data3 (inverse order)
				0xe6, 0x4a,
				// data4 (same order)
				0x8d, 0x28, 0xb4, 0x04, 0xdc, 0x7d, 0xaf, 0x63,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteGUID(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out uuid.UUID
		if err := dec.ReadGUID(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestNodeID(t *testing.T) {
	cases := []struct {
		in    ua.NodeID
		bytes []byte
	}{
		{
			ua.NewNodeIDNumeric(0, 255),
			[]byte{
				// mask
				0x00,
				// id
				0xff,
			},
		},
		{
			ua.NewNodeIDNumeric(2, 65535),
			[]byte{
				// mask
				0x01,
				// namespace
				0x02,
				// id
				0xff, 0xff,
			},
		},
		{
			ua.NewNodeIDNumeric(10, 4294967295),
			[]byte{
				// mask
				0x02,
				// namespace
				0x0a, 0x00,
				// id
				0xff, 0xff, 0xff, 0xff,
			},
		},
		{
			ua.NewNodeIDString(2, "bar"),
			[]byte{
				// mask
				0x03,
				// namespace
				0x02, 0x00,
				// value
				0x03, 0x00, 0x00, 0x00, // len
				0x62, 0x61, 0x72, // char
			},
		},
		{
			ua.NewNodeIDGUID(2, uuid.MustParse("AAAABBBB-CCDD-EEFF-0102-0123456789AB")),
			[]byte{
				// mask
				0x04,
				// namespace
				0x02, 0x00,
				// value
				// data1 (inverse order)
				0xbb, 0xbb, 0xaa, 0xaa,
				// data2 (inverse order)
				0xdd, 0xcc,
				// data3 (inverse order)
				0xff, 0xee,
				// data4 (same order)
				0x01, 0x02, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
			},
		},
		{
			ua.NewNodeIDOpaque(2, ua.ByteString("\x00\x10\x20\x30\x40\x50\x60\x70")),
			[]byte{
				// mask
				0x05,
				// namespace
				0x02, 0x00,
				// value
				0x08, 0x00, 0x00, 0x00, // len
				0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, // bytes
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteNodeID(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out ua.NodeID
		if err := dec.ReadNodeID(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestQualifiedName(t *testing.T) {
	cases := []struct {
		in    ua.QualifiedName
		bytes []byte
	}{
		{
			ua.QualifiedName{NamespaceIndex: 2, Name: "bar"},
			[]byte{
				0x02, 0x00,
				// name: "bar"
				0x03, 0x00, 0x00, 0x00, 0x62, 0x61, 0x72,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteQualifiedName(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out ua.QualifiedName
		if err := dec.ReadQualifiedName(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestLocalizedText(t *testing.T) {
	cases := []struct {
		in    ua.LocalizedText
		bytes []byte
	}{
		{
			ua.LocalizedText{},
			[]byte{0x00},
		},
		{
			ua.LocalizedText{Locale: "foo"},
			[]byte{
				0x01,
				0x03, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f,
			},
		},
		{
			ua.LocalizedText{Text: "bar"},
			[]byte{
				0x02,
				0x03, 0x00, 0x00, 0x00, 0x62, 0x61, 0x72,
			},
		},
		{
			ua.LocalizedText{Text: "bar", Locale: "foo"},
			[]byte{
				0x03,
				0x03, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f,
				// second String: "bar"
				0x03, 0x00, 0x00, 0x00, 0x62, 0x61, 0x72,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteLocalizedText(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out ua.LocalizedText
		if err := dec.ReadLocalizedText(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestDataValue(t *testing.T) {
	cases := []struct {
		in    ua.DataValue
		bytes []byte
	}{
		{
			ua.DataValue{float32(2.50025), 0, time.Time{}, 0, time.Time{}, 0},
			[]byte{
				// EncodingMask
				0x01,
				// Value
				0x0a,                   // type
				0x19, 0x04, 0x20, 0x40, // value
			},
		},
		{
			ua.DataValue{float32(2.50017), 0,
				time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC), 0,
				time.Date(2018, time.September, 17, 14, 28, 29, 112000000, time.UTC), 0},
			[]byte{
				// EncodingMask
				0x0d,
				// Value
				0x0a,                   // type
				0xc9, 0x02, 0x20, 0x40, // value
				// SourceTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
				// SeverTimestamp
				0x80, 0x3b, 0xe8, 0xb3, 0x92, 0x4e, 0xd4, 0x01,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteDataValue(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out ua.DataValue
		if err := dec.ReadDataValue(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestEnum(t *testing.T) {
	cases := []struct {
		in    ua.MessageSecurityMode
		bytes []byte
	}{
		{
			ua.MessageSecurityModeSignAndEncrypt,
			[]byte{
				0x03, 0x00, 0x00, 0x00,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.Encode(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out ua.MessageSecurityMode
		if err := dec.Decode(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestStruct(t *testing.T) {
	cases := []struct {
		in    interface{}
		out   interface{}
		bytes []byte
	}{
		{
			&ua.RequestHeader{Timestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC)},
			&ua.RequestHeader{},
			[]byte{
				0x00, 0x00, 0x00, 0xe0, 0x34, 0x95, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			&ua.ReadRequest{RequestHeader: ua.RequestHeader{Timestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC)}, NodesToRead: []ua.ReadValueID{{AttributeID: ua.AttributeIDValue, NodeID: ua.NewNodeIDNumeric(0, 255)}}},
			&ua.ReadRequest{},
			[]byte{
				0x00, 0x00, 0x00, 0xe0, 0x34, 0x95, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // max age
				0x00, 0x00, 0x00, 0x00, // timestamps
				0x01, 0x00, 0x00, 0x00, // len
				0x00, 0xff, 0x0d, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
			},
		},
		{
			&ua.PublishResponse{
				ResponseHeader:           ua.ResponseHeader{Timestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), RequestHandle: 1000085},
				SubscriptionID:           1296242973,
				AvailableSequenceNumbers: []uint32{4},
				MoreNotifications:        false,
				NotificationMessage: ua.NotificationMessage{
					SequenceNumber: 4,
					PublishTime:    time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC),
					NotificationData: []ua.ExtensionObject{
						ua.DataChangeNotification{
							MonitoredItems: []ua.MonitoredItemNotification{
								{ClientHandle: 9, Value: ua.DataValue{time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), 0, time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), 0, time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC), 0}},
							},
						},
					},
				},
				Results: []ua.StatusCode{0},
			},
			&ua.PublishResponse{},
			[]byte{
				0x00, 0xe0, 0x34, 0x95, 0x64, 0x00, 0x00, 0x00, 0x95, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, // header
				0x1d, 0x19, 0x43, 0x4d, // sub id
				0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // array of available seq id
				0x00,                   // more
				0x04, 0x00, 0x00, 0x00, // seq num
				0x00, 0xe0, 0x34, 0x95, 0x64, 0x00, 0x00, 0x00, // pub time
				0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2b, 0x03, 0x01, 0x26, 0x00, 0x00, 0x00, 0x01, 0x00,
				0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0d, 0x0d, 0x00, 0xe0, 0x34, 0x95, 0x64, 0x00, 0x00, 0x00,
				0x00, 0xe0, 0x34, 0x95, 0x64, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x34, 0x95, 0x64, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff, // diag infos
				0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // results
				0xff, 0xff, 0xff, 0xff, // diag infos
			},
		},
		{
			&ua.CreateSessionRequest{RequestHeader: ua.RequestHeader{Timestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC)}, ClientDescription: ua.ApplicationDescription{}},
			&ua.CreateSessionRequest{},
			[]byte{
				0x00, 0x00, 0x00, 0xe0, 0x34, 0x95, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
		},
	}

	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.Encode(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		if err := dec.Decode(c.out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, c.out, c.in)
	}
}

func TestSliceBoolean(t *testing.T) {
	cases := []struct {
		in    []bool
		bytes []byte
	}{
		{
			[]bool{true, false, true, false, true, false, true, false, true, false},
			[]byte{
				// int32 len
				0x0a, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteBooleanArray(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out []bool
		if err := dec.ReadBooleanArray(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestSliceVariant(t *testing.T) {
	cases := []struct {
		in    []ua.Variant
		bytes []byte
	}{
		{
			[]ua.Variant{
				true,
				"foo",
				uint16(255),
				float32(-6.5),
				ua.NewNodeIDNumeric(0, 1),
				ua.RequestHeader{Timestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC)},
				[]ua.ExtensionObject{
					ua.RequestHeader{Timestamp: time.Date(1601, time.January, 01, 12, 0, 0, 0, time.UTC)},
				},
				[]ua.Variant{
					true,
					"foo",
				},
			},
			[]byte{
				0x08, 0x00, 0x00, 0x00, // len
				0x01, 0x01, // bool
				0x0c, 0x03, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f, // string
				0x05, 0xff, 0x00, // uint16
				0x0a, 0x00, 0x00, 0xD0, 0xC0, // float
				0x11, 0x00, 0x01, // nodeid
				0x16, 0x01, 0x00, 0x87, 0x01, 0x01, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x34, 0x95, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ext obj
				0x96, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x87, 0x01, 0x01, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x34, 0x95, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // [] ext obj
				0x98, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x0c, 0x03, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f, // [] variant
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteVariantArray(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out []ua.Variant
		if err := dec.ReadVariantArray(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}

func TestSliceNodeID(t *testing.T) {
	cases := []struct {
		in    []ua.NodeID
		bytes []byte
	}{
		{
			[]ua.NodeID{
				ua.NewNodeIDNumeric(0, 255),
				ua.NewNodeIDNumeric(2, 65535),
				ua.NewNodeIDNumeric(10, 4294967295),
				ua.NewNodeIDString(2, "bar"),
				ua.NewNodeIDGUID(2, uuid.MustParse("AAAABBBB-CCDD-EEFF-0102-0123456789AB")),
				ua.NewNodeIDOpaque(2, ua.ByteString("\x00\x10\x20\x30\x40\x50\x60\x70")),
			},
			[]byte{
				0x06, 0x00, 0x00, 0x00, // len
				0x00, 0xff, // two-byte
				0x01, 0x02, 0xff, 0xff, // four-byte
				0x02, 0x0a, 0x00, 0xff, 0xff, 0xff, 0xff, // numeric
				0x03, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00, 0x62, 0x61, 0x72, // string
				0x04, 0x02, 0x00, 0xbb, 0xbb, 0xaa, 0xaa, 0xdd, 0xcc, 0xff, 0xee, 0x01, 0x02, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, // guid
				0x05, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, // bytes
			},
		},
	}
	for _, c := range cases {
		buf := &bytes.Buffer{}
		enc := ua.NewBinaryEncoder(buf, ua.NewEncodingContext())
		if err := enc.WriteNodeIDArray(c.in); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, buf.Bytes(), c.bytes)

		dec := ua.NewBinaryDecoder(buf, ua.NewEncodingContext())
		var out []ua.NodeID
		if err := dec.ReadNodeIDArray(&out); err != nil {
			t.Fatal(err)
		}
		assert.DeepEqual(t, out, c.in)
	}
}
