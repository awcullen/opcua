// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"encoding/binary"
	"io"
	"math"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/djherbis/buffer"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

var (
	// bytesPool is a pool of byte slices
	bytesPool           = sync.Pool{New: func() interface{} { s := make([]byte, 64*1024); return &s }}
	typeToEncoderMap    sync.Map
	typeDateTime        = reflect.TypeOf((*time.Time)(nil)).Elem()
	typeGUID            = reflect.TypeOf((*uuid.UUID)(nil)).Elem()
	typeNodeID          = reflect.TypeOf((*NodeID)(nil)).Elem()
	typeExpandedNodeID  = reflect.TypeOf((*ExpandedNodeID)(nil)).Elem()
	typeQualifiedName   = reflect.TypeOf((*QualifiedName)(nil)).Elem()
	typeLocalizedText   = reflect.TypeOf((*LocalizedText)(nil)).Elem()
	typeDataValue       = reflect.TypeOf((*DataValue)(nil)).Elem()
	typeExtensionObject = reflect.TypeOf((*ExtensionObject)(nil)).Elem()
	typeVariant         = reflect.TypeOf((*Variant)(nil)).Elem()
	typeDiagnosticInfo  = reflect.TypeOf((*DiagnosticInfo)(nil)).Elem()
	nilPtr              = unsafe.Pointer(nil)
)

type encoderFunc func(*BinaryEncoder, unsafe.Pointer) error

type interfaceHeader struct {
	typ *struct{}
	ptr unsafe.Pointer
}

type sliceHeader struct {
	data unsafe.Pointer
	len  int
	cap  int
}

// BinaryEncoder encodes the UA Binary protocol.
type BinaryEncoder struct {
	w  io.Writer
	ec EncodingContext
	bs [8]byte
}

// NewBinaryEncoder returns a new encoder that writes to an io.Writer.
func NewBinaryEncoder(w io.Writer, ec EncodingContext) *BinaryEncoder {
	return &BinaryEncoder{w, ec, [8]byte{}}
}

// Encode encodes the value using the UA Binary protocol.
func (enc *BinaryEncoder) Encode(v interface{}) error {
	typ := reflect.TypeOf(v)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	ptr := ((*interfaceHeader)(unsafe.Pointer(&v))).ptr

	// try to retrieve encoder from cache.
	if ef, ok := typeToEncoderMap.Load(typ); ok {

		// if found, call it.
		if err := ef.(encoderFunc)(enc, ptr); err != nil {
			return err
		}
		return nil
	}

	// build an encoder for the type and cache it.
	ef, err := getEncoder(typ)
	if err != nil {
		return err
	}
	typeToEncoderMap.Store(typ, ef)

	// call the encoder
	if err := ef(enc, ptr); err != nil {
		return err
	}
	return nil
}

func getEncoder(typ reflect.Type) (encoderFunc, error) {
	switch typ.Kind() {
	case reflect.Struct:
		switch typ {
		case typeDateTime:
			return getDateTimeEncoder()
		case typeGUID:
			return getGUIDEncoder()
		case typeExpandedNodeID:
			return getExpandedNodeIDEncoder()
		case typeQualifiedName:
			return getQualifiedNameEncoder()
		case typeLocalizedText:
			return getLocalizedTextEncoder()
		case typeDataValue:
			return getDataValueEncoder()
		case typeDiagnosticInfo:
			return getDiagnosticInfoEncoder()
		default:
			return getStructEncoder(typ)
		}
	case reflect.Slice:
		elemTyp := typ.Elem()
		switch elemTyp.Kind() {
		case reflect.Uint8:
			return getByteArrayEncoder()
		default:
			return getSliceEncoder(typ)
		}
	case reflect.Ptr:
		typ = typ.Elem()
		return getStructPtrEncoder(typ)
	case reflect.Interface:
		switch typ {
		case typeNodeID:
			return getNodeIDEncoder()
		case typeExtensionObject:
			return getExtensionObjectEncoder()
		case typeVariant:
			return getVariantEncoder()
		}
	case reflect.Bool:
		return getBooleanEncoder()
	case reflect.Int8:
		return getSByteEncoder()
	case reflect.Uint8:
		return getByteEncoder()
	case reflect.Int16:
		return getInt16Encoder()
	case reflect.Uint16:
		return getUInt16Encoder()
	case reflect.Int32:
		return getInt32Encoder()
	case reflect.Uint32:
		return getUInt32Encoder()
	case reflect.Int64:
		return getInt64Encoder()
	case reflect.Uint64:
		return getUInt64Encoder()
	case reflect.Float32:
		return getFloatEncoder()
	case reflect.Float64:
		return getDoubleEncoder()
	case reflect.String:
		return getStringEncoder()
	}
	return nil, errors.Errorf("unsupported type: %s\n", typ)
}

func getStructEncoder(typ reflect.Type) (encoderFunc, error) {
	encoders := []encoderFunc{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		enc, err := getEncoder(field.Type)
		if err != nil {
			return nil, err
		}
		offset := field.Offset
		encoders = append(encoders, func(buf *BinaryEncoder, p unsafe.Pointer) error {
			return enc(buf, unsafe.Pointer(uintptr(p)+offset))
		})
	}
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		for _, enc := range encoders {
			if err := enc(buf, p); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

func getStructPtrEncoder(typ reflect.Type) (encoderFunc, error) {
	encoders := []encoderFunc{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		enc, err := getEncoder(field.Type)
		if err != nil {
			return nil, err
		}
		offset := field.Offset
		encoders = append(encoders, func(buf *BinaryEncoder, p unsafe.Pointer) error {
			return enc(buf, unsafe.Pointer(uintptr(p)+offset))
		})
	}
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		p = unsafe.Pointer(*(**struct{})(p))
		if p == nilPtr {
			return BadEncodingError
		}
		for _, enc := range encoders {
			if err := enc(buf, p); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

func getSliceEncoder(typ reflect.Type) (encoderFunc, error) {
	elem := typ.Elem()
	elemSize := elem.Size()
	elemEncoder, err := getEncoder(elem)
	if err != nil {
		return nil, err
	}
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		hdr := *(*sliceHeader)(p)
		if hdr.len == 0 {
			if err := buf.WriteInt32(-1); err != nil {
				return err
			}
			return nil
		}
		if err := buf.WriteInt32(int32(hdr.len)); err != nil {
			return err
		}
		p2 := hdr.data
		for i := 0; i < hdr.len; i++ {
			if err := elemEncoder(buf, p2); err != nil {
				return err
			}
			p2 = unsafe.Pointer(uintptr(p2) + elemSize)
		}
		return nil
	}, nil
}
func getBooleanEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteBoolean(*(*bool)(p))
	}, nil
}
func getSByteEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteSByte(*(*int8)(p))
	}, nil
}
func getByteEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteByte(*(*uint8)(p))
	}, nil
}
func getInt16Encoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteInt16(*(*int16)(p))
	}, nil
}
func getUInt16Encoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteUInt16(*(*uint16)(p))
	}, nil
}
func getInt32Encoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteInt32(*(*int32)(p))
	}, nil
}
func getUInt32Encoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteUInt32(*(*uint32)(p))
	}, nil
}
func getInt64Encoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteInt64(*(*int64)(p))
	}, nil
}
func getUInt64Encoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteUInt64(*(*uint64)(p))
	}, nil
}
func getFloatEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteFloat(*(*float32)(p))
	}, nil
}
func getDoubleEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteDouble(*(*float64)(p))
	}, nil
}
func getStringEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteString(*(*string)(p))
	}, nil
}
func getNodeIDEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteNodeID(*(*NodeID)(p))
	}, nil
}
func getExpandedNodeIDEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteExpandedNodeID(*(*ExpandedNodeID)(p))
	}, nil
}
func getDateTimeEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteDateTime(*(*time.Time)(p))
	}, nil
}
func getGUIDEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteGUID(*(*uuid.UUID)(p))
	}, nil
}
func getQualifiedNameEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteQualifiedName(*(*QualifiedName)(p))
	}, nil
}
func getLocalizedTextEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteLocalizedText(*(*LocalizedText)(p))
	}, nil
}
func getExtensionObjectEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteExtensionObject(*(*ExtensionObject)(p))
	}, nil
}
func getVariantEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteVariant(*(*Variant)(p))
	}, nil
}
func getDataValueEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteDataValue(*(*DataValue)(p))
	}, nil
}
func getDiagnosticInfoEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteDiagnosticInfo(*(*DiagnosticInfo)(p))
	}, nil
}
func getByteArrayEncoder() (encoderFunc, error) {
	return func(buf *BinaryEncoder, p unsafe.Pointer) error {
		return buf.WriteByteArray(*(*[]uint8)(p))
	}, nil
}

// WriteBoolean writes a boolean.
func (enc *BinaryEncoder) WriteBoolean(value bool) error {
	if value {
		enc.bs[0] = 1
	} else {
		enc.bs[0] = 0
	}
	if _, err := enc.w.Write(enc.bs[:1]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteSByte writes a sbyte.
func (enc *BinaryEncoder) WriteSByte(value int8) error {
	enc.bs[0] = byte(value)
	if _, err := enc.w.Write(enc.bs[:1]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteByte writes a byte.
func (enc *BinaryEncoder) WriteByte(value byte) error {
	enc.bs[0] = value
	if _, err := enc.w.Write(enc.bs[:1]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteInt16 writes a int16.
func (enc *BinaryEncoder) WriteInt16(value int16) error {
	binary.LittleEndian.PutUint16(enc.bs[:2], uint16(value))
	if _, err := enc.w.Write(enc.bs[:2]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteUInt16 writes a uint16.
func (enc *BinaryEncoder) WriteUInt16(value uint16) error {
	binary.LittleEndian.PutUint16(enc.bs[:2], value)
	if _, err := enc.w.Write(enc.bs[:2]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteInt32 writes an int32.
func (enc *BinaryEncoder) WriteInt32(value int32) error {
	binary.LittleEndian.PutUint32(enc.bs[:4], uint32(value))
	if _, err := enc.w.Write(enc.bs[:4]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteUInt32 writes an uint32.
func (enc *BinaryEncoder) WriteUInt32(value uint32) error {
	binary.LittleEndian.PutUint32(enc.bs[:4], value)
	if _, err := enc.w.Write(enc.bs[:4]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteInt64 writes an int64.
func (enc *BinaryEncoder) WriteInt64(value int64) error {
	binary.LittleEndian.PutUint64(enc.bs[:8], uint64(value))
	if _, err := enc.w.Write(enc.bs[:8]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteUInt64 writes an uint64.
func (enc *BinaryEncoder) WriteUInt64(value uint64) error {
	binary.LittleEndian.PutUint64(enc.bs[:8], value)
	if _, err := enc.w.Write(enc.bs[:8]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteFloat writes a float.
func (enc *BinaryEncoder) WriteFloat(value float32) error {
	binary.LittleEndian.PutUint32(enc.bs[:4], math.Float32bits(value))
	if _, err := enc.w.Write(enc.bs[:4]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteDouble writes a double.
func (enc *BinaryEncoder) WriteDouble(value float64) error {
	binary.LittleEndian.PutUint64(enc.bs[:8], math.Float64bits(value))
	if _, err := enc.w.Write(enc.bs[:8]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteString writes a string.
func (enc *BinaryEncoder) WriteString(value string) error {
	if len(value) == 0 {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	// eliminate alloc of a second byte array.
	if _, err := enc.w.Write(
		*(*[]byte)(unsafe.Pointer(&sliceHeader{
			data: *(*unsafe.Pointer)(unsafe.Pointer(&value)),
			len:  len(value),
			cap:  len(value),
		}))); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteDateTime writes a date/time.
func (enc *BinaryEncoder) WriteDateTime(value time.Time) error {
	// ticks are 100 nanosecond intervals since January 1, 1601
	ticks := (value.Unix()+11644473600)*10000000 + int64(value.Nanosecond())/100
	if ticks < 0 {
		ticks = 0
	}
	if ticks >= 2650467743990000000 {
		ticks = 0x7FFFFFFFFFFFFFFF
	}
	if err := enc.WriteInt64(ticks); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteGUID writes a UUID
func (enc *BinaryEncoder) WriteGUID(value uuid.UUID) error {
	enc.bs[0] = value[3]
	enc.bs[1] = value[2]
	enc.bs[2] = value[1]
	enc.bs[3] = value[0]
	enc.bs[4] = value[5]
	enc.bs[5] = value[4]
	enc.bs[6] = value[7]
	enc.bs[7] = value[6]
	if _, err := enc.w.Write(enc.bs[:8]); err != nil {
		return BadEncodingError
	}
	if _, err := enc.w.Write(value[8:]); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteByteString writes a ByteString
func (enc *BinaryEncoder) WriteByteString(value ByteString) error {
	if len(value) == 0 {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	// eliminate alloc of a second byte array.
	if _, err := enc.w.Write(
		*(*[]byte)(unsafe.Pointer(&sliceHeader{
			data: *(*unsafe.Pointer)(unsafe.Pointer(&value)),
			len:  len(value),
			cap:  len(value),
		}))); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteXMLElement writes a XMLElement
func (enc *BinaryEncoder) WriteXMLElement(value XMLElement) error {
	return enc.WriteString(string(value))
}

// WriteNodeID writes a NodeID
func (enc *BinaryEncoder) WriteNodeID(value NodeID) error {
	switch value2 := value.(type) {
	case NodeIDNumeric:
		switch {
		case value2.ID <= 255 && value2.NamespaceIndex == 0:
			if err := enc.WriteByte(0x00); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteByte(byte(value2.ID)); err != nil {
				return BadEncodingError
			}
		case value2.ID <= 65535 && value2.NamespaceIndex <= 255:
			if err := enc.WriteByte(0x01); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteByte(byte(value2.NamespaceIndex)); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt16(uint16(value2.ID)); err != nil {
				return BadEncodingError
			}
		default:
			if err := enc.WriteByte(0x02); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt16(value2.NamespaceIndex); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt32(value2.ID); err != nil {
				return BadEncodingError
			}
		}
	case NodeIDString:
		if err := enc.WriteByte(0x03); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(value2.NamespaceIndex); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteString(value2.ID); err != nil {
			return BadEncodingError
		}
	case NodeIDGUID:
		if err := enc.WriteByte(0x04); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(value2.NamespaceIndex); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteGUID(value2.ID); err != nil {
			return BadEncodingError
		}
	case NodeIDOpaque:
		if err := enc.WriteByte(0x05); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(value2.NamespaceIndex); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByteString(value2.ID); err != nil {
			return BadEncodingError
		}
	default:
		if err := enc.WriteUInt16(0); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteExpandedNodeID writes an ExpandedNodeID
func (enc *BinaryEncoder) WriteExpandedNodeID(value ExpandedNodeID) error {
	var b byte
	if value.ServerIndex > 0 {
		b |= 0x40
	}
	if len(value.NamespaceURI) > 0 {
		b |= 0x80
	}
	switch value2 := value.NodeID.(type) {
	case NodeIDNumeric:
		ns := value2.NamespaceIndex
		if (b & 0x80) != 0 {
			ns = 0
		}
		switch {
		case value2.ID <= 255 && ns == 0:
			if err := enc.WriteByte(0x00 | b); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteByte(byte(value2.ID)); err != nil {
				return BadEncodingError
			}
		case value2.ID <= 65535 && ns <= 255:
			if err := enc.WriteByte(0x01 | b); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteByte(byte(ns)); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt16(uint16(value2.ID)); err != nil {
				return BadEncodingError
			}
		default:
			if err := enc.WriteByte(0x02 | b); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt16(ns); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt32(value2.ID); err != nil {
				return BadEncodingError
			}
		}
	case NodeIDString:
		ns := value2.NamespaceIndex
		if (b & 0x80) != 0 {
			ns = 0
		}
		if err := enc.WriteByte(0x03 | b); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(ns); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteString(value2.ID); err != nil {
			return BadEncodingError
		}
	case NodeIDGUID:
		ns := value2.NamespaceIndex
		if (b & 0x80) != 0 {
			ns = 0
		}
		if err := enc.WriteByte(0x04 | b); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(ns); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteGUID(value2.ID); err != nil {
			return BadEncodingError
		}
	case NodeIDOpaque:
		ns := value2.NamespaceIndex
		if (b & 0x80) != 0 {
			ns = 0
		}
		if err := enc.WriteByte(0x05 | b); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(ns); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByteString(value2.ID); err != nil {
			return BadEncodingError
		}
	default:
		if err := enc.WriteUInt16(0); err != nil {
			return BadEncodingError
		}
	}
	if (b & 0x80) != 0 {
		if err := enc.WriteString(value.NamespaceURI); err != nil {
			return BadEncodingError
		}
	}
	if (b & 0x40) != 0 {
		if err := enc.WriteUInt32(value.ServerIndex); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteStatusCode writes a StatusCode
func (enc *BinaryEncoder) WriteStatusCode(value StatusCode) error {
	if err := enc.WriteUInt32(uint32(value)); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteQualifiedName writes a QualifiedName
func (enc *BinaryEncoder) WriteQualifiedName(value QualifiedName) error {
	if err := enc.WriteUInt16(value.NamespaceIndex); err != nil {
		return BadEncodingError
	}
	return enc.WriteString(value.Name)
}

// WriteLocalizedText writes a LocalizedText
func (enc *BinaryEncoder) WriteLocalizedText(value LocalizedText) error {
	var b byte
	if value.Locale != "" {
		b |= 1
	}
	if value.Text != "" {
		b |= 2
	}
	if err := enc.WriteByte(b); err != nil {
		return BadEncodingError
	}
	if (b & 1) != 0 {
		if err := enc.WriteString(value.Locale); err != nil {
			return BadEncodingError
		}
	}
	if (b & 2) != 0 {
		if err := enc.WriteString(value.Text); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteExtensionObject writes an ExtensionObject
func (enc *BinaryEncoder) WriteExtensionObject(value ExtensionObject) error {
	if value == nil {
		if err := enc.WriteNodeID(nil); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByte(0x00); err != nil {
			return BadEncodingError
		}
		return nil
	}
	// lookup encoding id
	typ := reflect.TypeOf(value)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	id, ok := FindBinaryEncodingIDForType(typ)
	if !ok {
		return BadEncodingError
	}
	if err := enc.WriteNodeID(ToNodeID(id, enc.ec.NamespaceURIs())); err != nil {
		return BadEncodingError
	}
	if err := enc.WriteByte(0x01); err != nil {
		return BadEncodingError
	}
	// cast writer to BufferAt to access superpowers
	if buf, ok := enc.w.(buffer.BufferAt); ok {
		mark := buf.Len() // mark where length is written
		bs := make([]byte, 4)
		if _, err := buf.Write(bs); err != nil {
			return BadEncodingError
		}
		start := buf.Len() // mark where encoding starts
		if err := enc.Encode(value); err != nil {
			return BadEncodingError
		}
		end := buf.Len() // mark where encoding ends
		binary.LittleEndian.PutUint32(bs, uint32(end-start))
		// write actual length at mark
		if _, err := buf.WriteAt(bs, mark); err != nil {
			return BadEncodingError
		}
		return nil
	}

	// fall back to using extra buffer
	buf2 := *(bytesPool.Get().(*[]byte))
	defer bytesPool.Put(&buf2)
	var writer = NewWriter(buf2)
	enc2 := NewBinaryEncoder(writer, enc.ec)
	if err := enc2.Encode(value); err != nil {
		return BadEncodingError
	}
	if err := enc.WriteByteArray(writer.Bytes()); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteDataValue writes a DataValue
func (enc *BinaryEncoder) WriteDataValue(value DataValue) error {
	var b byte
	if value.Value != nil {
		b |= 1
	}

	if value.StatusCode != 0 {
		b |= 2
	}

	if !value.SourceTimestamp.IsZero() {
		b |= 4
	}

	if value.SourcePicoseconds != 0 {
		b |= 16
	}

	if !value.ServerTimestamp.IsZero() {
		b |= 8
	}

	if value.ServerPicoseconds != 0 {
		b |= 32
	}

	if err := enc.WriteByte(b); err != nil {
		return err
	}
	if (b & 1) != 0 {
		if err := enc.WriteVariant(value.Value); err != nil {
			return BadEncodingError
		}
	}

	if (b & 2) != 0 {
		if err := enc.WriteUInt32(uint32(value.StatusCode)); err != nil {
			return BadEncodingError
		}
	}

	if (b & 4) != 0 {
		if err := enc.WriteDateTime(value.SourceTimestamp); err != nil {
			return BadEncodingError
		}
	}

	if (b & 16) != 0 {
		if err := enc.WriteUInt16(value.SourcePicoseconds); err != nil {
			return BadEncodingError
		}
	}

	if (b & 8) != 0 {
		if err := enc.WriteDateTime(value.ServerTimestamp); err != nil {
			return BadEncodingError
		}
	}

	if (b & 32) != 0 {
		if err := enc.WriteUInt16(value.ServerPicoseconds); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteVariant writes a Variant
func (enc *BinaryEncoder) WriteVariant(value Variant) error {
	switch v1 := value.(type) {
	case nil:
		return enc.WriteByte(0)
	case bool:
		if err := enc.WriteByte(VariantTypeBoolean); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteBoolean(v1); err != nil {
			return BadEncodingError
		}
	case int8:
		if err := enc.WriteByte(VariantTypeSByte); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteSByte(v1); err != nil {
			return BadEncodingError
		}
	case uint8:
		if err := enc.WriteByte(VariantTypeByte); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByte(v1); err != nil {
			return BadEncodingError
		}
	case int16:
		if err := enc.WriteByte(VariantTypeInt16); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteInt16(v1); err != nil {
			return BadEncodingError
		}
	case uint16:
		if err := enc.WriteByte(VariantTypeUInt16); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(v1); err != nil {
			return BadEncodingError
		}
	case int32:
		if err := enc.WriteByte(VariantTypeInt32); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteInt32(v1); err != nil {
			return BadEncodingError
		}
	case uint32:
		if err := enc.WriteByte(VariantTypeUInt32); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt32(v1); err != nil {
			return BadEncodingError
		}
	case int64:
		if err := enc.WriteByte(VariantTypeInt64); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteInt64(v1); err != nil {
			return BadEncodingError
		}
	case uint64:
		if err := enc.WriteByte(VariantTypeUInt64); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt64(v1); err != nil {
			return BadEncodingError
		}
	case float32:
		if err := enc.WriteByte(VariantTypeFloat); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteFloat(v1); err != nil {
			return BadEncodingError
		}
	case float64:
		if err := enc.WriteByte(VariantTypeDouble); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteDouble(v1); err != nil {
			return BadEncodingError
		}
	case string:
		if err := enc.WriteByte(VariantTypeString); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteString(v1); err != nil {
			return BadEncodingError
		}
	case time.Time:
		if err := enc.WriteByte(VariantTypeDateTime); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteDateTime(v1); err != nil {
			return BadEncodingError
		}
	case uuid.UUID:
		if err := enc.WriteByte(VariantTypeGUID); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteGUID(v1); err != nil {
			return BadEncodingError
		}
	case ByteString:
		if err := enc.WriteByte(VariantTypeByteString); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByteString(v1); err != nil {
			return BadEncodingError
		}
	case XMLElement:
		if err := enc.WriteByte(VariantTypeXMLElement); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteXMLElement(v1); err != nil {
			return BadEncodingError
		}
	case NodeID:
		if err := enc.WriteByte(VariantTypeNodeID); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteNodeID(v1); err != nil {
			return BadEncodingError
		}
	case ExpandedNodeID:
		if err := enc.WriteByte(VariantTypeExpandedNodeID); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteExpandedNodeID(v1); err != nil {
			return BadEncodingError
		}
	case StatusCode:
		if err := enc.WriteByte(VariantTypeStatusCode); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteStatusCode(v1); err != nil {
			return BadEncodingError
		}
	case QualifiedName:
		if err := enc.WriteByte(VariantTypeQualifiedName); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteQualifiedName(v1); err != nil {
			return BadEncodingError
		}
	case LocalizedText:
		if err := enc.WriteByte(VariantTypeLocalizedText); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteLocalizedText(v1); err != nil {
			return BadEncodingError
		}
	// case ExtensionObject:
	// 	if err := enc.WriteByte(VariantTypeExtensionObject); err != nil {
	// 		return BadEncodingError
	// 	}
	// 	if err := enc.WriteExtensionObject(v1); err != nil {
	// 		return BadEncodingError
	// 	}
	case []bool:
		if err := enc.WriteByte(VariantTypeBoolean | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteBooleanArray(v1); err != nil {
			return BadEncodingError
		}
	case []int8:
		if err := enc.WriteByte(VariantTypeSByte | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteSByteArray(v1); err != nil {
			return BadEncodingError
		}
	case []uint8:
		if err := enc.WriteByte(VariantTypeByte | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByteArray(v1); err != nil {
			return BadEncodingError
		}
	case []int16:
		if err := enc.WriteByte(VariantTypeInt16 | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteInt16Array(v1); err != nil {
			return BadEncodingError
		}
	case []uint16:
		if err := enc.WriteByte(VariantTypeUInt16 | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16Array(v1); err != nil {
			return BadEncodingError
		}
	case []int32:
		if err := enc.WriteByte(VariantTypeInt32 | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteInt32Array(v1); err != nil {
			return BadEncodingError
		}
	case []uint32:
		if err := enc.WriteByte(VariantTypeUInt32 | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt32Array(v1); err != nil {
			return BadEncodingError
		}
	case []int64:
		if err := enc.WriteByte(VariantTypeInt64 | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteInt64Array(v1); err != nil {
			return BadEncodingError
		}
	case []uint64:
		if err := enc.WriteByte(VariantTypeUInt64 | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt64Array(v1); err != nil {
			return BadEncodingError
		}
	case []float32:
		if err := enc.WriteByte(VariantTypeFloat | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteFloatArray(v1); err != nil {
			return BadEncodingError
		}
	case []float64:
		if err := enc.WriteByte(VariantTypeDouble | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteDoubleArray(v1); err != nil {
			return BadEncodingError
		}
	case []string:
		if err := enc.WriteByte(VariantTypeString | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteStringArray(v1); err != nil {
			return BadEncodingError
		}
	case []time.Time:
		if err := enc.WriteByte(VariantTypeDateTime | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteDateTimeArray(v1); err != nil {
			return BadEncodingError
		}
	case []uuid.UUID:
		if err := enc.WriteByte(VariantTypeGUID | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteGUIDArray(v1); err != nil {
			return BadEncodingError
		}
	case []ByteString:
		if err := enc.WriteByte(VariantTypeByteString | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByteStringArray(v1); err != nil {
			return BadEncodingError
		}
	case []XMLElement:
		if err := enc.WriteByte(VariantTypeXMLElement | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteXMLElementArray(v1); err != nil {
			return BadEncodingError
		}
	case []NodeID:
		if err := enc.WriteByte(VariantTypeNodeID | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteNodeIDArray(v1); err != nil {
			return BadEncodingError
		}
	case []ExpandedNodeID:
		if err := enc.WriteByte(VariantTypeExpandedNodeID | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteExpandedNodeIDArray(v1); err != nil {
			return BadEncodingError
		}
	case []StatusCode:
		if err := enc.WriteByte(VariantTypeStatusCode | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteStatusCodeArray(v1); err != nil {
			return BadEncodingError
		}
	case []QualifiedName:
		if err := enc.WriteByte(VariantTypeQualifiedName | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteQualifiedNameArray(v1); err != nil {
			return BadEncodingError
		}
	case []LocalizedText:
		if err := enc.WriteByte(VariantTypeLocalizedText | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteLocalizedTextArray(v1); err != nil {
			return BadEncodingError
		}
	case []ExtensionObject:
		if err := enc.WriteByte(VariantTypeExtensionObject | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteExtensionObjectArray(v1); err != nil {
			return BadEncodingError
		}
	case []DataValue:
		if err := enc.WriteByte(VariantTypeDataValue | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteDataValueArray(v1); err != nil {
			return BadEncodingError
		}
	case []Variant:
		if err := enc.WriteByte(VariantTypeVariant | 128); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteVariantArray(v1); err != nil {
			return BadEncodingError
		}
	default:
		// wrap structs in ExtensionObject
		if err := enc.WriteByte(VariantTypeExtensionObject); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteExtensionObject(v1); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteDiagnosticInfo writes a DiagnosticInfo
func (enc *BinaryEncoder) WriteDiagnosticInfo(value DiagnosticInfo) error {
	var b byte
	if value.SymbolicID != nil {
		b |= 1
	}
	if value.NamespaceURI != nil {
		b |= 2
	}
	if value.Locale != nil {
		b |= 8
	}
	if value.LocalizedText != nil {
		b |= 4
	}
	if value.AdditionalInfo != nil {
		b |= 16
	}
	if value.InnerStatusCode != nil {
		b |= 32
	}
	if value.InnerDiagnosticInfo != nil {
		b |= 64
	}
	if err := enc.WriteByte(b); err != nil {
		return err
	}
	if (b & 1) != 0 {
		if err := enc.WriteInt32(*value.SymbolicID); err != nil {
			return err
		}
	}
	if (b & 2) != 0 {
		if err := enc.WriteInt32(*value.NamespaceURI); err != nil {
			return err
		}
	}
	if (b & 8) != 0 {
		if err := enc.WriteInt32(*value.Locale); err != nil {
			return err
		}
	}
	if (b & 4) != 0 {
		if err := enc.WriteInt32(*value.LocalizedText); err != nil {
			return err
		}
	}
	if (b & 16) != 0 {
		if err := enc.WriteString(*value.AdditionalInfo); err != nil {
			return err
		}
	}

	if (b & 32) != 0 {
		if err := enc.WriteStatusCode(*value.InnerStatusCode); err != nil {
			return err
		}
	}

	if (b & 64) != 0 {
		if err := enc.WriteDiagnosticInfo(*value.InnerDiagnosticInfo); err != nil {
			return err
		}
	}
	return nil
}

// WriteBooleanArray writes a bool array.
func (enc *BinaryEncoder) WriteBooleanArray(value []bool) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteBoolean(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteSByteArray writes a int8 array.
func (enc *BinaryEncoder) WriteSByteArray(value []int8) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteSByte(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteByteArray writes a byte array.
func (enc *BinaryEncoder) WriteByteArray(value []byte) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	if _, err := enc.w.Write(value); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteInt16Array writes a int16 array.
func (enc *BinaryEncoder) WriteInt16Array(value []int16) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteInt16(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteUInt16Array writes a uint16 array.
func (enc *BinaryEncoder) WriteUInt16Array(value []uint16) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteUInt16(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteInt32Array writes a int32 array.
func (enc *BinaryEncoder) WriteInt32Array(value []int32) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteInt32(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteUInt32Array writes a uint32 array.
func (enc *BinaryEncoder) WriteUInt32Array(value []uint32) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteUInt32(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteInt64Array writes a int64 array.
func (enc *BinaryEncoder) WriteInt64Array(value []int64) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteInt64(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteUInt64Array writes a uint64 array.
func (enc *BinaryEncoder) WriteUInt64Array(value []uint64) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteUInt64(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteFloatArray writes a float32 array.
func (enc *BinaryEncoder) WriteFloatArray(value []float32) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteFloat(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteDoubleArray writes a float64 array.
func (enc *BinaryEncoder) WriteDoubleArray(value []float64) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteDouble(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteStringArray writes a string array.
func (enc *BinaryEncoder) WriteStringArray(value []string) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteString(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteDateTimeArray writes a Time array.
func (enc *BinaryEncoder) WriteDateTimeArray(value []time.Time) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteDateTime(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteGUIDArray writes a UUID array.
func (enc *BinaryEncoder) WriteGUIDArray(value []uuid.UUID) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteGUID(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteByteStringArray writes a ByteString array.
func (enc *BinaryEncoder) WriteByteStringArray(value []ByteString) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteByteString(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteXMLElementArray writes a XMLElement array.
func (enc *BinaryEncoder) WriteXMLElementArray(value []XMLElement) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteXMLElement(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteNodeIDArray writes a NodeID array.
func (enc *BinaryEncoder) WriteNodeIDArray(value []NodeID) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteNodeID(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteExpandedNodeIDArray writes an ExpandedNodeID array.
func (enc *BinaryEncoder) WriteExpandedNodeIDArray(value []ExpandedNodeID) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteExpandedNodeID(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteStatusCodeArray writes a StatusCode array.
func (enc *BinaryEncoder) WriteStatusCodeArray(value []StatusCode) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteStatusCode(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteQualifiedNameArray writes a QualifiedName array.
func (enc *BinaryEncoder) WriteQualifiedNameArray(value []QualifiedName) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteQualifiedName(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteLocalizedTextArray writes a LocalizedText array.
func (enc *BinaryEncoder) WriteLocalizedTextArray(value []LocalizedText) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteLocalizedText(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteExtensionObjectArray writes an ExtensionObject array.
func (enc *BinaryEncoder) WriteExtensionObjectArray(value []ExtensionObject) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteExtensionObject(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteDataValueArray writes a DataValue array.
func (enc *BinaryEncoder) WriteDataValueArray(value []DataValue) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteDataValue(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteVariantArray writes a Variant array.
func (enc *BinaryEncoder) WriteVariantArray(value []Variant) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteVariant(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteDiagnosticInfoArray writes a DiagnosticInfo array.
func (enc *BinaryEncoder) WriteDiagnosticInfoArray(value []DiagnosticInfo) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteDiagnosticInfo(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}
