// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"encoding/binary"
	"io"
	"math"
	"reflect"
	"time"
	"unsafe"

	"github.com/djherbis/buffer"
	uuid "github.com/google/uuid"
)

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

// Encode encodes the value using the UA Binary protocol and writes the bytes to the io.writer.
func (enc *BinaryEncoder) Encode(value interface{}) error {
	// fmt.Printf("Encode %T\n", value)
	switch val := value.(type) {
	case bool:
		return enc.WriteBoolean(val)
	case int8:
		return enc.WriteSByte(val)
	case uint8:
		return enc.WriteByte(val)
	case int16:
		return enc.WriteInt16(val)
	case uint16:
		return enc.WriteUInt16(val)
	case int32:
		return enc.WriteInt32(val)
	case uint32:
		return enc.WriteUInt32(val)
	case int64:
		return enc.WriteInt64(val)
	case uint64:
		return enc.WriteUInt64(val)
	case float32:
		return enc.WriteFloat(val)
	case float64:
		return enc.WriteDouble(val)
	case string:
		return enc.WriteString(val)
	case time.Time:
		return enc.WriteDateTime(val)
	case uuid.UUID:
		return enc.WriteGUID(val)
	case ByteString:
		return enc.WriteByteString(val)
	case XMLElement:
		return enc.WriteXMLElement(val)
	case NodeID:
		return enc.WriteNodeID(val)
	case ExpandedNodeID:
		return enc.WriteExpandedNodeID(val)
	case StatusCode:
		return enc.WriteStatusCode(val)
	case QualifiedName:
		return enc.WriteQualifiedName(val)
	case LocalizedText:
		return enc.WriteLocalizedText(val)
	case *ExtensionObject:
		return enc.WriteExtensionObject(val)
	case *DataValue:
		return enc.WriteDataValue(val)
	case *Variant:
		return enc.WriteVariant(val)
	case *DiagnosticInfo:
		return enc.WriteDiagnosticInfo(val)
	case []bool:
		return enc.WriteBooleanArray(val)
	case []int8:
		return enc.WriteSByteArray(val)
	case []uint8:
		return enc.WriteByteArray(val)
	case []int16:
		return enc.WriteInt16Array(val)
	case []uint16:
		return enc.WriteUInt16Array(val)
	case []int32:
		return enc.WriteInt32Array(val)
	case []uint32:
		return enc.WriteUInt32Array(val)
	case []int64:
		return enc.WriteInt64Array(val)
	case []uint64:
		return enc.WriteUInt64Array(val)
	case []float32:
		return enc.WriteFloatArray(val)
	case []float64:
		return enc.WriteDoubleArray(val)
	case []string:
		return enc.WriteStringArray(val)
	case []time.Time:
		return enc.WriteDateTimeArray(val)
	case []uuid.UUID:
		return enc.WriteGUIDArray(val)
	case []ByteString:
		return enc.WriteByteStringArray(val)
	case []XMLElement:
		return enc.WriteXMLElementArray(val)
	case []NodeID:
		return enc.WriteNodeIDArray(val)
	case []ExpandedNodeID:
		return enc.WriteExpandedNodeIDArray(val)
	case []StatusCode:
		return enc.WriteStatusCodeArray(val)
	case []QualifiedName:
		return enc.WriteQualifiedNameArray(val)
	case []LocalizedText:
		return enc.WriteLocalizedTextArray(val)
	case []*ExtensionObject:
		return enc.WriteExtensionObjectArray(val)
	case []*DataValue:
		return enc.WriteDataValueArray(val)
	case []*Variant:
		return enc.WriteVariantArray(val)
	case []*DiagnosticInfo:
		return enc.WriteDiagnosticInfoArray(val)
	default:
		rv := reflect.ValueOf(value)
		for rv.Kind() == reflect.Ptr {
			rv = rv.Elem()
		}
		switch rv.Kind() {
		case reflect.Int32: // e.g. enums
			return enc.WriteInt32((int32)(rv.Int()))

		case reflect.Struct: // e.g. ReadRequest
			typ := rv.Type()
			for i := 0; i < typ.NumField(); i++ {
				field := rv.Field(i)
				switch field.Kind() {

				case reflect.Ptr: // *struct, e.g. *ApplicationDescription, *DataValue
					if field.IsNil() {
						if err := enc.Encode(reflect.New(field.Type().Elem()).Interface()); err != nil {
							return BadEncodingError
						}
						continue
					}
					if err := enc.Encode(field.Interface()); err != nil {
						return BadEncodingError
					}

				case reflect.Interface: // interface{}, e.g. *UserNameIdentityToken
					// fmt.Printf("Encode interface{}\n")
					if err := enc.WriteStructureAsExtensionObject(field.Interface()); err != nil {
						return BadEncodingError
					}

				default: // built-in, []built-in, enum, []enum, struct, []struct, []*struct, []interface{}
					if err := enc.Encode(field.Interface()); err != nil {
						return BadEncodingError
					}
				}
			}
			return nil

		case reflect.Slice: // [] , e.g. []*ReadValueID, []interface{}
			len := rv.Len()
			if err := enc.WriteInt32(int32(len)); err != nil {
				return BadEncodingError
			}
			for i := 0; i < len; i++ {
				elem := rv.Index(i)
				switch elem.Kind() {

				case reflect.Ptr: // e.g. *ReadValueID
					if elem.IsNil() {
						return BadEncodingError
					}
					if err := enc.Encode(elem.Interface()); err != nil {
						return BadEncodingError
					}

				case reflect.Interface: // e.g. interface{}
					if elem.IsNil() {
						return BadEncodingError
					}
					if err := enc.WriteStructureAsExtensionObject(elem.Interface()); err != nil {
						return BadEncodingError
					}

				default: // built-in, struct, enum
					if err := enc.Encode(elem.Interface()); err != nil {
						return BadEncodingError
					}
				}
			}
			return nil

		default:
			return BadEncodingError
		}
	}
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
	// eliminate alloc of a second byte array and copying of one byte array to another.
	var bytes []byte
	str := (*stringHeader2)(unsafe.Pointer(&value))
	slice := (*sliceHeader2)(unsafe.Pointer(&bytes))
	slice.Data = str.Data
	slice.Len = str.Len
	slice.Cap = str.Len
	if _, err := enc.w.Write(bytes); err != nil {
		return BadEncodingError
	}
	return nil
}

type sliceHeader2 struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

type stringHeader2 struct {
	Data unsafe.Pointer
	Len  int
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
	// eliminate alloc of a second byte array and copying of one byte array to another.
	var bytes []byte
	str := (*stringHeader2)(unsafe.Pointer(&value))
	slice := (*sliceHeader2)(unsafe.Pointer(&bytes))
	slice.Data = str.Data
	slice.Len = str.Len
	slice.Cap = str.Len
	if _, err := enc.w.Write(bytes); err != nil {
		return BadEncodingError
	}
	return nil
}

// WriteXMLElement writes a XmlElement
func (enc *BinaryEncoder) WriteXMLElement(value XMLElement) error {
	return enc.WriteString(string(value))
}

// WriteNodeID writes a NodeID
func (enc *BinaryEncoder) WriteNodeID(value NodeID) error {
	switch value.idType {
	case IDTypeNumeric:
		switch {
		case value.nid <= 255 && value.namespaceIndex == 0:
			if err := enc.WriteByte(0x00); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteByte(byte(value.nid)); err != nil {
				return BadEncodingError
			}
		case value.nid <= 65535 && value.namespaceIndex <= 255:
			if err := enc.WriteByte(0x01); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteByte(byte(value.namespaceIndex)); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt16(uint16(value.nid)); err != nil {
				return BadEncodingError
			}
		default:
			if err := enc.WriteByte(0x02); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt16(value.namespaceIndex); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt32(value.nid); err != nil {
				return BadEncodingError
			}
		}
	case IDTypeString:
		if err := enc.WriteByte(0x03); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(value.namespaceIndex); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteString(value.sid); err != nil {
			return BadEncodingError
		}
	case IDTypeGUID:
		if err := enc.WriteByte(0x04); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(value.namespaceIndex); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteGUID(value.gid); err != nil {
			return BadEncodingError
		}
	case IDTypeOpaque:
		if err := enc.WriteByte(0x05); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(value.namespaceIndex); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByteString(value.bid); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteExpandedNodeID writes an ExpandedNodeID
func (enc *BinaryEncoder) WriteExpandedNodeID(value ExpandedNodeID) error {
	svr := value.ServerIndex()
	nsu := value.NamespaceURI()
	ns := value.NamespaceIndex()
	var b byte
	if len(nsu) > 0 {
		b |= 0x80
		ns = 0
	}
	if svr > 0 {
		b |= 0x40
	}
	switch value.nodeID.idType {
	case IDTypeNumeric:
		id := value.nodeID.nid
		switch {
		case id <= 255 && ns == 0:
			if err := enc.WriteByte(0x00 | b); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteByte(byte(id)); err != nil {
				return BadEncodingError
			}
		case id <= 65535 && ns <= 255:
			if err := enc.WriteByte(0x01 | b); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteByte(byte(ns)); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt16(uint16(id)); err != nil {
				return BadEncodingError
			}
		default:
			if err := enc.WriteByte(0x02 | b); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt16(ns); err != nil {
				return BadEncodingError
			}
			if err := enc.WriteUInt32(id); err != nil {
				return BadEncodingError
			}
		}
	case IDTypeString:
		id := value.nodeID.sid
		if err := enc.WriteByte(0x03 | b); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(ns); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteString(id); err != nil {
			return BadEncodingError
		}
	case IDTypeGUID:
		id := value.nodeID.gid
		if err := enc.WriteByte(0x04 | b); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(ns); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteGUID(id); err != nil {
			return BadEncodingError
		}
	case IDTypeOpaque:
		id := value.nodeID.bid
		if err := enc.WriteByte(0x05 | b); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteUInt16(ns); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByteString(id); err != nil {
			return BadEncodingError
		}
	}
	if (b & 0x80) != 0 {
		if err := enc.WriteString(nsu); err != nil {
			return BadEncodingError
		}
	}
	if (b & 0x40) != 0 {
		if err := enc.WriteUInt32(svr); err != nil {
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

// WriteStructureAsExtensionObject writes an structure as an ExtensionObject
func (enc *BinaryEncoder) WriteStructureAsExtensionObject(value interface{}) error {
	// fmt.Printf("Encoder writing StructureAsExtensionObject\n")
	if value == nil {
		if err := enc.WriteUInt16(0); err != nil {
			return err
		}
		return enc.WriteByte(0x00)
	}
	// lookup encoding id
	id, ok := findBinaryEncodingIDForType(reflect.TypeOf(value).Elem())
	if !ok {
		return BadEncodingError
	}
	if err := enc.WriteNodeID(id.ToNodeID(enc.ec.NamespaceURIs())); err != nil {
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
	// if BufferAt interface not available
	buf2 := buffer.NewPartitionAt(bufferPool)
	enc2 := NewBinaryEncoder(buf2, enc.ec)
	if err := enc2.Encode(value); err != nil {
		buf2.Reset()
		return BadEncodingError
	}
	enc.WriteInt32(int32(buf2.Len()))
	buf3 := bytesPool.Get().([]byte)
	if _, err := io.CopyBuffer(enc.w, buf2, buf3); err != nil {
		bytesPool.Put(buf3)
		buf2.Reset()
		return BadEncodingError
	}
	bytesPool.Put(buf3)
	buf2.Reset()
	return nil
}

// WriteExtensionObject writes an ExtensionObject
func (enc *BinaryEncoder) WriteExtensionObject(value *ExtensionObject) error {
	switch value.Encoding() {
	case ExtensionObjectEncodingNone:
		if err := enc.WriteNodeID(NilNodeID); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByte(0x00); err != nil {
			return BadEncodingError
		}
		return nil

	case ExtensionObjectEncodingByteString:
		if err := enc.WriteNodeID(value.TypeID().ToNodeID(enc.ec.NamespaceURIs())); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByte(0x01); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByteString(value.Body().(ByteString)); err != nil {
			return BadEncodingError
		}
		return nil

	case ExtensionObjectEncodingXMLElement:
		if err := enc.WriteNodeID(value.TypeID().ToNodeID(enc.ec.NamespaceURIs())); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteByte(0x02); err != nil {
			return BadEncodingError
		}
		if err := enc.WriteXMLElement(value.Body().(XMLElement)); err != nil {
			return BadEncodingError
		}
		return nil
	}
	return BadEncodingError
}

// WriteDataValue writes a DataValue
func (enc *BinaryEncoder) WriteDataValue(value *DataValue) error {
	if value == nil {
		return enc.WriteByte(0)
	}
	var b byte
	if !value.InnerVariant().IsNil() {
		b |= 1
	}

	if value.StatusCode() != 0 {
		b |= 2
	}

	if !value.SourceTimestamp().IsZero() {
		b |= 4
	}

	if value.SourcePicoseconds() != 0 {
		b |= 16
	}

	if !value.ServerTimestamp().IsZero() {
		b |= 8
	}

	if value.ServerPicoseconds() != 0 {
		b |= 32
	}

	if err := enc.WriteByte(b); err != nil {
		return err
	}
	if (b & 1) != 0 {
		if err := enc.WriteVariant(value.InnerVariant()); err != nil {
			return BadEncodingError
		}
	}

	if (b & 2) != 0 {
		if err := enc.WriteUInt32(uint32(value.StatusCode())); err != nil {
			return BadEncodingError
		}
	}

	if (b & 4) != 0 {
		if err := enc.WriteDateTime(value.SourceTimestamp()); err != nil {
			return BadEncodingError
		}
	}

	if (b & 16) != 0 {
		if err := enc.WriteUInt16(value.SourcePicoseconds()); err != nil {
			return BadEncodingError
		}
	}

	if (b & 8) != 0 {
		if err := enc.WriteDateTime(value.ServerTimestamp()); err != nil {
			return BadEncodingError
		}
	}

	if (b & 32) != 0 {
		if err := enc.WriteUInt16(value.ServerPicoseconds()); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteVariant writes a Variant
func (enc *BinaryEncoder) WriteVariant(value *Variant) error {
	if value.IsNil() {
		return enc.WriteByte(0)
	}
	b := byte(value.Type())

	if len(value.ArrayDimensions()) == 0 {
		if err := enc.WriteByte(b); err != nil {
			return BadEncodingError
		}
		switch value.Type() {
		case VariantTypeBoolean:
			v, ok := value.value.(bool)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteBoolean(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeSByte:
			v, ok := value.value.(int8)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteSByte(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeByte:
			v, ok := value.value.(byte)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteByte(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeInt16:
			v, ok := value.value.(int16)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteInt16(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeUInt16:
			v, ok := value.value.(uint16)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteUInt16(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeInt32:
			v, ok := value.value.(int32)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteInt32(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeUInt32:
			v, ok := value.value.(uint32)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteUInt32(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeInt64:
			v, ok := value.value.(int64)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteInt64(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeUInt64:
			v, ok := value.value.(uint64)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteUInt64(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeFloat:
			v, ok := value.value.(float32)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteFloat(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeDouble:
			v, ok := value.value.(float64)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteDouble(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeString:
			v, ok := value.value.(string)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteString(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeDateTime:
			v, ok := value.value.(time.Time)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteDateTime(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeGUID:
			v, ok := value.value.(uuid.UUID)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteGUID(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeByteString:
			v, ok := value.value.(ByteString)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteByteString(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeXMLElement:
			v, ok := value.value.(XMLElement)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteXMLElement(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeNodeID:
			v, ok := value.value.(NodeID)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteNodeID(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeExpandedNodeID:
			v, ok := value.value.(ExpandedNodeID)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteExpandedNodeID(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeStatusCode:
			v, ok := value.value.(StatusCode)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteStatusCode(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeQualifiedName:
			v, ok := value.value.(QualifiedName)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteQualifiedName(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeLocalizedText:
			v, ok := value.value.(LocalizedText)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteLocalizedText(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeExtensionObject:
			switch v := value.value.(type) {
			case *ExtensionObject:
				if err := enc.WriteExtensionObject(v); err != nil {
					return BadEncodingError
				}
			default:
				if err := enc.WriteStructureAsExtensionObject(v); err != nil {
					return BadEncodingError
				}
			}

		case VariantTypeDataValue:
			v, ok := value.value.(*DataValue)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteDataValue(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeVariant:
			v, ok := value.value.(*Variant)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteVariant(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeDiagnosticInfo:
			v, ok := value.value.(*DiagnosticInfo)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteDiagnosticInfo(v); err != nil {
				return BadEncodingError
			}

		default:
			return BadEncodingError
		}
		return nil
	}

	b |= 128 // an array

	if len(value.ArrayDimensions()) == 1 {
		enc.WriteByte(b)
		switch value.Type() {
		case VariantTypeBoolean:
			v, ok := value.value.([]bool)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteBooleanArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeSByte:
			v, ok := value.value.([]int8)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteSByteArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeByte:
			v, ok := value.value.([]byte)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteByteArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeInt16:
			v, ok := value.value.([]int16)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteInt16Array(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeUInt16:
			v, ok := value.value.([]uint16)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteUInt16Array(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeInt32:
			v, ok := value.value.([]int32)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteInt32Array(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeUInt32:
			v, ok := value.value.([]uint32)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteUInt32Array(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeInt64:
			v, ok := value.value.([]int64)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteInt64Array(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeUInt64:
			v, ok := value.value.([]uint64)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteUInt64Array(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeFloat:
			v, ok := value.value.([]float32)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteFloatArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeDouble:
			v, ok := value.value.([]float64)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteDoubleArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeString:
			v, ok := value.value.([]string)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteStringArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeDateTime:
			v, ok := value.value.([]time.Time)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteDateTimeArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeGUID:
			v, ok := value.value.([]uuid.UUID)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteGUIDArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeByteString:
			v, ok := value.value.([]ByteString)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteByteStringArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeXMLElement:
			v, ok := value.value.([]XMLElement)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteXMLElementArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeNodeID:
			v, ok := value.value.([]NodeID)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteNodeIDArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeExpandedNodeID:
			v, ok := value.value.([]ExpandedNodeID)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteExpandedNodeIDArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeStatusCode:
			v, ok := value.value.([]StatusCode)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteStatusCodeArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeQualifiedName:
			v, ok := value.value.([]QualifiedName)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteQualifiedNameArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeLocalizedText:
			v, ok := value.value.([]LocalizedText)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteLocalizedTextArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeExtensionObject:
			switch v := value.value.(type) {
			case []*ExtensionObject:
				if err := enc.WriteExtensionObjectArray(v); err != nil {
					return BadEncodingError
				}
			case []interface{}:
				if err := enc.WriteStructureAsExtensionObjectArray(v); err != nil {
					return BadEncodingError
				}
			default:
				return BadEncodingError
			}

		case VariantTypeDataValue:
			v, ok := value.value.([]*DataValue)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteDataValueArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeVariant:
			v, ok := value.value.([]*Variant)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteVariantArray(v); err != nil {
				return BadEncodingError
			}

		case VariantTypeDiagnosticInfo:
			v, ok := value.value.([]*DiagnosticInfo)
			if !ok {
				return BadEncodingError
			}
			if err := enc.WriteDiagnosticInfoArray(v); err != nil {
				return BadEncodingError
			}

		default:
			return BadEncodingError
		}
		return nil
	}

	// TODO: Multidimensional array
	return BadEncodingError
}

// WriteDiagnosticInfo writes a DiagnosticInfo
func (enc *BinaryEncoder) WriteDiagnosticInfo(value *DiagnosticInfo) error {
	if value == nil {
		return enc.WriteByte(0)
	}
	var b byte
	if value.SymbolicID() >= 0 {
		b |= 1
	}

	if value.NamespaceURI() >= 0 {
		b |= 2
	}

	if value.Locale() >= 0 {
		b |= 8
	}

	if value.LocalizedText() >= 0 {
		b |= 4
	}

	if len(value.AdditionalInfo()) > 0 {
		b |= 16
	}

	if value.InnerStatusCode() != 0 {
		b |= 32
	}

	if value.InnerDiagnosticInfo() != nil {
		b |= 64
	}

	if err := enc.WriteByte(b); err != nil {
		return err
	}
	if (b & 1) != 0 {
		if err := enc.WriteInt32(value.SymbolicID()); err != nil {
			return err
		}
	}

	if (b & 2) != 0 {
		if err := enc.WriteInt32(value.NamespaceURI()); err != nil {
			return err
		}
	}

	if (b & 8) != 0 {
		if err := enc.WriteInt32(value.Locale()); err != nil {
			return err
		}
	}

	if (b & 4) != 0 {
		if err := enc.WriteInt32(value.LocalizedText()); err != nil {
			return err
		}
	}

	if (b & 16) != 0 {
		if err := enc.WriteString(value.AdditionalInfo()); err != nil {
			return err
		}
	}

	if (b & 32) != 0 {
		if err := enc.WriteStatusCode(value.InnerStatusCode()); err != nil {
			return err
		}
	}

	if (b & 64) != 0 {
		if err := enc.WriteDiagnosticInfo(value.InnerDiagnosticInfo()); err != nil {
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

// WriteXMLElementArray writes a XmlElement array.
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

// WriteStructureAsExtensionObjectArray writes a slice of structures as an ExtensionObjectArray
func (enc *BinaryEncoder) WriteStructureAsExtensionObjectArray(value []interface{}) error {
	if value == nil {
		return enc.WriteInt32(-1)
	}
	if err := enc.WriteInt32(int32(len(value))); err != nil {
		return BadEncodingError
	}
	for i := range value {
		if err := enc.WriteStructureAsExtensionObject(value[i]); err != nil {
			return BadEncodingError
		}
	}
	return nil
}

// WriteExtensionObjectArray writes an ExtensionObject array.
func (enc *BinaryEncoder) WriteExtensionObjectArray(value []*ExtensionObject) error {
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
func (enc *BinaryEncoder) WriteDataValueArray(value []*DataValue) error {
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
func (enc *BinaryEncoder) WriteVariantArray(value []*Variant) error {
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
func (enc *BinaryEncoder) WriteDiagnosticInfoArray(value []*DiagnosticInfo) error {
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
