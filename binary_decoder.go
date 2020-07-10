// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"encoding/binary"
	"io"
	"math"
	"reflect"
	"time"
	"unsafe"

	uuid "github.com/google/uuid"
)

// BinaryDecoder decodes the UA binary protocol.
type BinaryDecoder struct {
	r  io.Reader
	ec EncodingContext
	bs [8]byte
}

// NewBinaryDecoder returns a new decoder that reads from an io.Reader.
func NewBinaryDecoder(r io.Reader, ec EncodingContext) *BinaryDecoder {
	return &BinaryDecoder{r, ec, [8]byte{}}
}

// Decode decodes a value.
func (dec *BinaryDecoder) Decode(value interface{}) error {
	// fmt.Printf("Decode %T\n", value)
	switch val := value.(type) {
	case *bool:
		return dec.ReadBoolean(val)
	case *int8:
		return dec.ReadSByte(val)
	case *uint8:
		return dec.ReadByte(val)
	case *int16:
		return dec.ReadInt16(val)
	case *uint16:
		return dec.ReadUInt16(val)
	case *int32:
		return dec.ReadInt32(val)
	case *uint32:
		return dec.ReadUInt32(val)
	case *int64:
		return dec.ReadInt64(val)
	case *uint64:
		return dec.ReadUInt64(val)
	case *float32:
		return dec.ReadFloat(val)
	case *float64:
		return dec.ReadDouble(val)
	case *string:
		return dec.ReadString(val)
	case *time.Time:
		return dec.ReadDateTime(val)
	case *uuid.UUID:
		return dec.ReadGUID(val)
	case *ByteString:
		return dec.ReadByteString(val)
	case *XMLElement:
		return dec.ReadXMLElement(val)
	case *NodeID:
		return dec.ReadNodeID(val)
	case *ExpandedNodeID:
		return dec.ReadExpandedNodeID(val)
	case *StatusCode:
		return dec.ReadStatusCode(val)
	case *QualifiedName:
		return dec.ReadQualifiedName(val)
	case *LocalizedText:
		return dec.ReadLocalizedText(val)
	case **ExtensionObject:
		return dec.ReadExtensionObject(val)
	case **DataValue:
		return dec.ReadDataValue(val)
	case **Variant:
		return dec.ReadVariant(val)
	case **DiagnosticInfo:
		return dec.ReadDiagnosticInfo(val)
	case *[]bool:
		return dec.ReadBooleanArray(val)
	case *[]int8:
		return dec.ReadSByteArray(val)
	case *[]uint8:
		return dec.ReadByteArray(val)
	case *[]int16:
		return dec.ReadInt16Array(val)
	case *[]uint16:
		return dec.ReadUInt16Array(val)
	case *[]int32:
		return dec.ReadInt32Array(val)
	case *[]uint32:
		return dec.ReadUInt32Array(val)
	case *[]int64:
		return dec.ReadInt64Array(val)
	case *[]uint64:
		return dec.ReadUInt64Array(val)
	case *[]float32:
		return dec.ReadFloatArray(val)
	case *[]float64:
		return dec.ReadDoubleArray(val)
	case *[]string:
		return dec.ReadStringArray(val)
	case *[]time.Time:
		return dec.ReadDateTimeArray(val)
	case *[]uuid.UUID:
		return dec.ReadGUIDArray(val)
	case *[]ByteString:
		return dec.ReadByteStringArray(val)
	case *[]XMLElement:
		return dec.ReadXMLElementArray(val)
	case *[]NodeID:
		return dec.ReadNodeIDArray(val)
	case *[]ExpandedNodeID:
		return dec.ReadExpandedNodeIDArray(val)
	case *[]StatusCode:
		return dec.ReadStatusCodeArray(val)
	case *[]QualifiedName:
		return dec.ReadQualifiedNameArray(val)
	case *[]LocalizedText:
		return dec.ReadLocalizedTextArray(val)
	case *[]*ExtensionObject:
		return dec.ReadExtensionObjectArray(val)
	case *[]*DataValue:
		return dec.ReadDataValueArray(val)
	case *[]*Variant:
		return dec.ReadVariantArray(val)
	case *[]*DiagnosticInfo:
		return dec.ReadDiagnosticInfoArray(val)
	default:
		rv := reflect.ValueOf(value).Elem()
		for rv.Kind() == reflect.Ptr {
			if rv.IsNil() {
				rv.Set(reflect.New(rv.Type().Elem()))
				// fmt.Printf("new %s \n", rv.String())
			}
			rv = rv.Elem()
		}
		switch rv.Kind() {
		case reflect.Int32: // e.g. enums
			var v int32
			if err := dec.ReadInt32(&v); err != nil {
				return BadDecodingError
			}
			rv.SetInt(int64(v))
			return nil

		case reflect.Interface: // e.g. interface{}
			// fmt.Printf("interface \n")
			var v interface{}
			if err := dec.ReadObject(&v); err != nil {
				return BadDecodingError
			}
			// fmt.Printf("interface read %+v \n", v)
			if v != nil {
				rv.Set(reflect.ValueOf(v))
			}
			return nil

		// case reflect.Ptr: // e.g. *ReadRequest
		// 	fmt.Printf("Ptr struct \n")
		// 	var v = reflect.New(rv.Type().Elem()).Interface()
		// 	if err := dec.Decode(&v); err != nil {
		// 		return BadDecodingError
		// 	}
		// 	fmt.Printf("Ptr struct read %+v \n", v)
		// 	rv.Set(reflect.ValueOf(v))
		// 	return nil

		case reflect.Struct: // e.g. RequestHeader
			typ := rv.Type()
			for i := 0; i < typ.NumField(); i++ {
				field := rv.Field(i)
				// fmt.Printf("Decode field: %s\n", typ.Field(i).Name)
				switch field.Kind() {

				case reflect.Ptr: // e.g. *ApplicationDescription
					if field.IsNil() {
						field.Set(reflect.New(field.Type().Elem()))
						// fmt.Printf("new %s \n", field.String())
					}
					if err := dec.Decode(field.Addr().Interface()); err != nil {
						return BadEncodingError
					}

					// 		case reflect.Interface: // e.g. interface{}
					// 			if field.IsNil() {
					// 				if err := enc.WriteExtensionObject(&NilExtensionObject); err != nil {
					// 					return BadEncodingError
					// 				}
					// 				continue
					// 			}
					// 			id, ok := findBinaryEncodingIDForType(field.Elem().Type())
					// 			if !ok {
					// 				return BadEncodingError
					// 			}
					// 			if err := enc.WriteNodeID(id.ToNodeID(enc.ec.NamespaceURIs())); err != nil {
					// 				return BadEncodingError
					// 			}
					// 			if err := enc.WriteByte(0x01); err != nil {
					// 				return BadEncodingError
					// 			}
					// 			// cast writer to BufferAt to access superpowers
					// 			if buf, ok := enc.w.(buffer.BufferAt); ok {
					// 				mark := buf.Len() // mark where length is written
					// 				bs := make([]byte, 4)
					// 				if _, err := buf.Write(bs); err != nil {
					// 					return BadEncodingError
					// 				}
					// 				start := buf.Len() // mark where encoding starts
					// 				if err := enc.Encode(field.Interface()); err != nil {
					// 					return BadEncodingError
					// 				}
					// 				end := buf.Len() // mark where encoding ends
					// 				binary.LittleEndian.PutUint32(bs, uint32(end-start))
					// 				// write actual length at mark
					// 				if _, err := buf.WriteAt(bs, mark); err != nil {
					// 					return BadEncodingError
					// 				}
					// 				continue
					// 			}
					// 			// if BufferAt interface not available
					// 			buf2 := buffer.NewPartitionAt(bufferPool)
					// 			enc2 := NewBinaryEncoder(buf2, enc.ec)
					// 			if err := enc2.Encode(field.Interface()); err != nil {
					// 				buf2.Reset()
					// 				return BadEncodingError
					// 			}
					// 			enc.WriteInt32(int32(buf2.Len()))
					// 			buf3 := bytesPool.Get().([]byte)
					// 			if _, err := io.CopyBuffer(enc.w, buf2, buf3); err != nil {
					// 				bytesPool.Put(buf3)
					// 				buf2.Reset()
					// 				return BadEncodingError
					// 			}
					// 			bytesPool.Put(buf3)
					// 			buf2.Reset()

				default:
					if err := dec.Decode(field.Addr().Interface()); err != nil {
						return BadEncodingError
					}
				}
			} // end for
			return nil

		case reflect.Slice: // e.g. []*ReadValueID , []interface{}
			var num int32
			if err := dec.ReadInt32(&num); err != nil {
				return BadDecodingError
			}
			// fmt.Printf("Decode slice: %s\n", rv.Type().String())
			if num < 0 {
				// fmt.Printf("Setting zero: %s\n", rv.Type().String())
				rv.Set(reflect.Zero(rv.Type()))
				return nil
			}
			len := int(num)
			// fmt.Printf("Making slice: %s\n", rv.Type().String())
			slc := reflect.MakeSlice(rv.Type(), len, len)
			elemType := rv.Type().Elem()
			isPtr := elemType.Kind() == reflect.Ptr
			for i := 0; i < len; i++ {
				elem := slc.Index(i)
				if isPtr {
					// fmt.Printf("New elem: %s\n", elemType.String())
					elem.Set(reflect.New(elemType.Elem()))
				}
				if err := dec.Decode(elem.Addr().Interface()); err != nil {
					return BadDecodingError
				}
			}
			rv.Set(slc)
			return nil

		default:
			return BadDecodingError

		}
	}
}

// ReadBoolean reads a bool.
func (dec *BinaryDecoder) ReadBoolean(value *bool) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:1]); err != nil {
		return BadDecodingError
	}
	*value = dec.bs[0] != 0
	return nil
}

// ReadSByte reads a int8.
func (dec *BinaryDecoder) ReadSByte(value *int8) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:1]); err != nil {
		return BadDecodingError
	}
	*value = int8(dec.bs[0])
	return nil
}

// ReadByte reads a byte.
func (dec *BinaryDecoder) ReadByte(value *byte) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:1]); err != nil {
		return BadDecodingError
	}
	*value = dec.bs[0]
	return nil
}

// ReadInt16 reads a int16.
func (dec *BinaryDecoder) ReadInt16(value *int16) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:2]); err != nil {
		return BadDecodingError
	}
	*value = int16(binary.LittleEndian.Uint16(dec.bs[:2]))
	return nil
}

// ReadUInt16 reads a uint16.
func (dec *BinaryDecoder) ReadUInt16(value *uint16) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:2]); err != nil {
		return BadDecodingError
	}
	*value = binary.LittleEndian.Uint16(dec.bs[:2])
	return nil
}

// ReadInt32 reads a int32.
func (dec *BinaryDecoder) ReadInt32(value *int32) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:4]); err != nil {
		return BadDecodingError
	}
	*value = int32(binary.LittleEndian.Uint32(dec.bs[:4]))
	return nil
}

// ReadUInt32 reads a uint32.
func (dec *BinaryDecoder) ReadUInt32(value *uint32) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:4]); err != nil {
		return BadDecodingError
	}
	*value = binary.LittleEndian.Uint32(dec.bs[:4])
	return nil
}

// ReadInt64 reads a int64.
func (dec *BinaryDecoder) ReadInt64(value *int64) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:8]); err != nil {
		return BadDecodingError
	}
	*value = int64(binary.LittleEndian.Uint64(dec.bs[:8]))
	return nil
}

// ReadUInt64 reads a int64.
func (dec *BinaryDecoder) ReadUInt64(value *uint64) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:8]); err != nil {
		return BadDecodingError
	}
	*value = binary.LittleEndian.Uint64(dec.bs[:8])
	return nil
}

// ReadFloat reads a float32.
func (dec *BinaryDecoder) ReadFloat(value *float32) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:4]); err != nil {
		return BadDecodingError
	}
	*value = math.Float32frombits(binary.LittleEndian.Uint32(dec.bs[:4]))
	return nil
}

// ReadDouble reads a float64.
func (dec *BinaryDecoder) ReadDouble(value *float64) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:8]); err != nil {
		return BadDecodingError
	}
	*value = math.Float64frombits(binary.LittleEndian.Uint64(dec.bs[:8]))
	return nil
}

// ReadString reads a string.
func (dec *BinaryDecoder) ReadString(value *string) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = ""
		return nil
	}
	bs := make([]byte, num)
	if _, err := io.ReadFull(dec.r, bs); err != nil {
		return BadDecodingError
	}
	// eliminate alloc of a second byte array and copying from one byte array to another.
	*value = *(*string)(unsafe.Pointer(&bs))
	return nil
}

// ReadDateTime reads a time.Time.
func (dec *BinaryDecoder) ReadDateTime(value *time.Time) error {
	// ticks are 100 nanosecond intervals since January 1, 1601
	var ticks int64
	if err := dec.ReadInt64(&ticks); err != nil {
		return BadDecodingError
	}
	if ticks < 0 {
		ticks = 0
	}
	if ticks == 0x7FFFFFFFFFFFFFFF {
		ticks = 2650467743990000000
	}
	*value = time.Unix(ticks/10000000-11644473600, (ticks%10000000)*100).UTC()
	return nil
}

// ReadGUID reads a uuid.UUID.
func (dec *BinaryDecoder) ReadGUID(value *uuid.UUID) error {
	if _, err := io.ReadFull(dec.r, dec.bs[:8]); err != nil {
		return BadDecodingError
	}
	value[0] = dec.bs[3]
	value[1] = dec.bs[2]
	value[2] = dec.bs[1]
	value[3] = dec.bs[0]
	value[4] = dec.bs[5]
	value[5] = dec.bs[4]
	value[6] = dec.bs[7]
	value[7] = dec.bs[6]

	if _, err := io.ReadFull(dec.r, value[8:]); err != nil {
		return BadDecodingError
	}
	return nil
}

// ReadByteString reads a ByteString.
func (dec *BinaryDecoder) ReadByteString(value *ByteString) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num <= 0 {
		*value = ""
		return nil
	}
	bs := make([]byte, num)
	if _, err := io.ReadFull(dec.r, bs); err != nil {
		return BadDecodingError
	}
	*value = *(*ByteString)(unsafe.Pointer(&bs))
	return nil
}

// ReadXMLElement reads a XmlElement.
func (dec *BinaryDecoder) ReadXMLElement(value *XMLElement) error {
	var s string
	if err := dec.ReadString(&s); err != nil {
		return BadDecodingError
	}
	*value = XMLElement(s)
	return nil
}

// ReadNodeID reads a NodeID.
func (dec *BinaryDecoder) ReadNodeID(value *NodeID) error {
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	switch b {
	case 0x00:
		var id byte
		if err := dec.ReadByte(&id); err != nil {
			return BadDecodingError
		}
		*value = NewNodeIDNumeric(uint16(0), uint32(id))
		return nil

	case 0x01:
		var ns byte
		if err := dec.ReadByte(&ns); err != nil {
			return BadDecodingError
		}
		var id uint16
		if err := dec.ReadUInt16(&id); err != nil {
			return BadDecodingError
		}
		*value = NewNodeIDNumeric(uint16(ns), uint32(id))
		return nil

	case 0x02:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id uint32
		if err := dec.ReadUInt32(&id); err != nil {
			return BadDecodingError
		}
		*value = NewNodeIDNumeric(ns, uint32(id))
		return nil

	case 0x03:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id string
		if err := dec.ReadString(&id); err != nil {
			return BadDecodingError
		}
		*value = NewNodeIDString(ns, id)
		return nil

	case 0x04:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id uuid.UUID
		if err := dec.ReadGUID(&id); err != nil {
			return BadDecodingError
		}
		*value = NewNodeIDGUID(ns, id)
		return nil

	case 0x05:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id ByteString
		if err := dec.ReadByteString(&id); err != nil {
			return BadDecodingError
		}
		*value = NewNodeIDOpaque(ns, id)
		return nil

	default:
		return BadDecodingError
	}
}

// ReadExpandedNodeID reads an ExpandedNodeID.
func (dec *BinaryDecoder) ReadExpandedNodeID(value *ExpandedNodeID) error {
	var (
		n   NodeID
		nsu string
		svr uint32
		b   byte
	)
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	switch b & 0x0F {
	case 0x00:
		var id byte
		if err := dec.ReadByte(&id); err != nil {
			return BadDecodingError
		}
		n = NewNodeIDNumeric(uint16(0), uint32(id))
	case 0x01:
		var ns byte
		if err := dec.ReadByte(&ns); err != nil {
			return BadDecodingError
		}
		var id uint16
		if err := dec.ReadUInt16(&id); err != nil {
			return BadDecodingError
		}
		n = NewNodeIDNumeric(uint16(ns), uint32(id))

	case 0x02:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id uint32
		if err := dec.ReadUInt32(&id); err != nil {
			return BadDecodingError
		}
		n = NewNodeIDNumeric(ns, id)

	case 0x03:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id string
		if err := dec.ReadString(&id); err != nil {
			return BadDecodingError
		}
		n = NewNodeIDString(ns, id)

	case 0x04:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id uuid.UUID
		if err := dec.ReadGUID(&id); err != nil {
			return BadDecodingError
		}
		n = NewNodeIDGUID(ns, id)

	case 0x05:
		var ns uint16
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		var id ByteString
		if err := dec.ReadByteString(&id); err != nil {
			return BadDecodingError
		}
		n = NewNodeIDOpaque(ns, id)

	default:
		return BadDecodingError
	}

	if (b & 0x80) != 0 {
		if err := dec.ReadString(&nsu); err != nil {
			return BadDecodingError
		}
	}

	if (b & 0x40) != 0 {
		if err := dec.ReadUInt32(&svr); err != nil {
			return BadDecodingError
		}
	}
	*value = ExpandedNodeID{svr, nsu, n}
	return nil
}

// ReadStatusCode reads a StatusCode.
func (dec *BinaryDecoder) ReadStatusCode(value *StatusCode) error {
	var u1 uint32
	if err := dec.ReadUInt32(&u1); err != nil {
		return BadDecodingError
	}
	*value = StatusCode(u1)
	return nil
}

// ReadQualifiedName reads a QualifiedName.
func (dec *BinaryDecoder) ReadQualifiedName(value *QualifiedName) error {
	var ns uint16
	if err := dec.ReadUInt16(&ns); err != nil {
		return BadDecodingError
	}
	var name string
	if err := dec.ReadString(&name); err != nil {
		return BadDecodingError
	}
	*value = QualifiedName{ns, name}
	return nil
}

// ReadLocalizedText reads a LocalizedText.
func (dec *BinaryDecoder) ReadLocalizedText(value *LocalizedText) error {
	var (
		text   string
		locale string
		b      byte
	)
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	if (b & 1) != 0 {
		if err := dec.ReadString(&locale); err != nil {
			return BadDecodingError
		}
	}
	if (b & 2) != 0 {
		if err := dec.ReadString(&text); err != nil {
			return BadDecodingError
		}
	}
	*value = LocalizedText{text, locale}
	return nil
}

// ReadObject reads an object.
func (dec *BinaryDecoder) ReadObject(value *interface{}) error {
	var nodeID NodeID
	if err := dec.ReadNodeID(&nodeID); err != nil {
		return BadDecodingError
	}
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	switch b {
	case 0x00:
		*value = nil
		return nil
	case 0x01:
		id := nodeID.ToExpandedNodeID(dec.ec.NamespaceURIs())
		// lookup type
		typ, ok := findTypeForBinaryEncodingID(id)
		if ok {
			var unused int32
			if err := dec.ReadInt32(&unused); err != nil {
				return BadDecodingError
			}
			obj := reflect.New(typ).Interface()
			if err := dec.Decode(obj); err != nil {
				return BadDecodingError
			}
			*value = obj
			return nil
		}
		var body ByteString
		if err := dec.ReadByteString(&body); err != nil {
			return BadDecodingError
		}
		*value = NewExtensionObjectByteString(body, id)
		return nil
	case 0x02:
		id := nodeID.ToExpandedNodeID(dec.ec.NamespaceURIs())
		var body XMLElement
		if err := dec.ReadXMLElement(&body); err != nil {
			return BadDecodingError
		}
		*value = NewExtensionObjectXMLElement(body, id)
		return nil
	default:
		return BadDecodingError
	}
}

// ReadExtensionObject reads an Extensionobject.
func (dec *BinaryDecoder) ReadExtensionObject(value **ExtensionObject) error {
	var nodeID NodeID
	if err := dec.ReadNodeID(&nodeID); err != nil {
		return BadDecodingError
	}
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	switch b {
	case 0x00:
		*value = &NilExtensionObject
		return nil
	case 0x01:
		id := nodeID.ToExpandedNodeID(dec.ec.NamespaceURIs())
		var body ByteString
		if err := dec.ReadByteString(&body); err != nil {
			return BadDecodingError
		}
		*value = NewExtensionObjectByteString(body, id)
		return nil
	case 0x02:
		id := nodeID.ToExpandedNodeID(dec.ec.NamespaceURIs())
		var body XMLElement
		if err := dec.ReadXMLElement(&body); err != nil {
			return BadDecodingError
		}
		*value = NewExtensionObjectXMLElement(body, id)
		return nil
	default:
		return BadDecodingError
	}
}

// ReadDataValue reads a DataValue.
func (dec *BinaryDecoder) ReadDataValue(value **DataValue) error {
	var (
		v                 *Variant
		statusCode        StatusCode
		sourceTimestamp   time.Time
		sourcePicoseconds uint16
		serverTimestamp   time.Time
		serverPicoseconds uint16
		b                 byte
	)
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	if (b & 1) != 0 {
		if err := dec.ReadVariant(&v); err != nil {
			return BadDecodingError
		}
	} else {
		v = &NilVariant
	}
	if (b & 2) != 0 {
		if err := dec.ReadStatusCode(&statusCode); err != nil {
			return BadDecodingError
		}
	}
	if (b & 4) != 0 {
		if err := dec.ReadDateTime(&sourceTimestamp); err != nil {
			return BadDecodingError
		}
	}
	if (b & 16) != 0 {
		if err := dec.ReadUInt16(&sourcePicoseconds); err != nil {
			return BadDecodingError
		}
	}
	if (b & 8) != 0 {
		if err := dec.ReadDateTime(&serverTimestamp); err != nil {
			return BadDecodingError
		}
	}

	if (b & 32) != 0 {
		if err := dec.ReadUInt16(&serverPicoseconds); err != nil {
			return BadDecodingError
		}
	}
	*value = &DataValue{v, statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
	return nil
}

// ReadVariant reads a Variant.
func (dec *BinaryDecoder) ReadVariant(value **Variant) error {
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}

	if (b & 0x80) == 0 {
		switch b & 0x3F {
		case 0:
			*value = &NilVariant
			return nil

		case 1:
			var v bool
			if err := dec.ReadBoolean(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeBoolean, []int32{}}
			return nil

		case 2:
			var v int8
			if err := dec.ReadSByte(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeSByte, []int32{}}
			return nil

		case 3:
			var v byte
			if err := dec.ReadByte(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeByte, []int32{}}
			return nil

		case 4:
			var v int16
			if err := dec.ReadInt16(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeInt16, []int32{}}
			return nil

		case 5:
			var v uint16
			if err := dec.ReadUInt16(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeUInt16, []int32{}}
			return nil

		case 6:
			var v int32
			if err := dec.ReadInt32(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeInt32, []int32{}}
			return nil

		case 7:
			var v uint32
			if err := dec.ReadUInt32(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeUInt32, []int32{}}
			return nil

		case 8:
			var v int64
			if err := dec.ReadInt64(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeInt64, []int32{}}
			return nil

		case 9:
			var v uint64
			if err := dec.ReadUInt64(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeUInt64, []int32{}}
			return nil

		case 10:
			var v float32
			if err := dec.ReadFloat(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeFloat, []int32{}}
			return nil

		case 11:
			var v float64
			if err := dec.ReadDouble(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeDouble, []int32{}}
			return nil

		case 12:
			var v string
			if err := dec.ReadString(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeString, []int32{}}
			return nil

		case 13:
			var v time.Time
			if err := dec.ReadDateTime(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeDateTime, []int32{}}
			return nil

		case 14:
			var v uuid.UUID
			if err := dec.ReadGUID(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeGUID, []int32{}}
			return nil

		case 15:
			var v ByteString
			if err := dec.ReadByteString(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeByteString, []int32{}}
			return nil

		case 16:
			var v XMLElement
			if err := dec.ReadXMLElement(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeXMLElement, []int32{}}
			return nil

		case 17:
			var v NodeID
			if err := dec.ReadNodeID(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeNodeID, []int32{}}
			return nil

		case 18:
			var v ExpandedNodeID
			if err := dec.ReadExpandedNodeID(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeExpandedNodeID, []int32{}}
			return nil

		case 19:
			var v StatusCode
			if err := dec.ReadStatusCode(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeStatusCode, []int32{}}
			return nil

		case 20:
			var v QualifiedName
			if err := dec.ReadQualifiedName(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeQualifiedName, []int32{}}
			return nil

		case 21:
			var v LocalizedText
			if err := dec.ReadLocalizedText(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeLocalizedText, []int32{}}
			return nil

		case 22:
			var v interface{}
			if err := dec.ReadObject(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeExtensionObject, []int32{}}
			return nil

		case 23:
			var v *DataValue
			if err := dec.ReadDataValue(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeDataValue, []int32{}}
			return nil

		case 24:
			var v *Variant
			if err := dec.ReadVariant(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeVariant, []int32{}}
			return nil

		case 25:
			var v *DiagnosticInfo
			if err := dec.ReadDiagnosticInfo(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeDiagnosticInfo, []int32{}}
			return nil

		default:
			return BadDecodingError
		}
	}

	if (b & 0x40) == 0 {
		switch b & 0x3F {
		case 0:
			*value = &NilVariant
			return nil

		case 1:
			var v []bool
			if err := dec.ReadBooleanArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeBoolean, []int32{int32(len(v))}}
			return nil

		case 2:
			var v []int8
			if err := dec.ReadSByteArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeSByte, []int32{int32(len(v))}}
			return nil

		case 3:
			var v []byte
			if err := dec.ReadByteArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeByte, []int32{int32(len(v))}}
			return nil

		case 4:
			var v []int16
			if err := dec.ReadInt16Array(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeInt16, []int32{int32(len(v))}}
			return nil

		case 5:
			var v []uint16
			if err := dec.ReadUInt16Array(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeUInt16, []int32{int32(len(v))}}
			return nil

		case 6:
			var v []int32
			if err := dec.ReadInt32Array(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeInt32, []int32{int32(len(v))}}
			return nil

		case 7:
			var v []uint32
			if err := dec.ReadUInt32Array(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeUInt32, []int32{int32(len(v))}}
			return nil

		case 8:
			var v []int64
			if err := dec.ReadInt64Array(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeInt64, []int32{int32(len(v))}}
			return nil

		case 9:
			var v []uint64
			if err := dec.ReadUInt64Array(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeUInt64, []int32{int32(len(v))}}
			return nil

		case 10:
			var v []float32
			if err := dec.ReadFloatArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeFloat, []int32{int32(len(v))}}
			return nil

		case 11:
			var v []float64
			if err := dec.ReadDoubleArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeDouble, []int32{int32(len(v))}}
			return nil

		case 12:
			var v []string
			if err := dec.ReadStringArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeString, []int32{int32(len(v))}}
			return nil

		case 13:
			var v []time.Time
			if err := dec.ReadDateTimeArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeDateTime, []int32{int32(len(v))}}
			return nil

		case 14:
			var v []uuid.UUID
			if err := dec.ReadGUIDArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeGUID, []int32{int32(len(v))}}
			return nil

		case 15:
			var v []ByteString
			if err := dec.ReadByteStringArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeByteString, []int32{int32(len(v))}}
			return nil

		case 16:
			var v []XMLElement
			if err := dec.ReadXMLElementArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeXMLElement, []int32{int32(len(v))}}
			return nil

		case 17:
			var v []NodeID
			if err := dec.ReadNodeIDArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeNodeID, []int32{int32(len(v))}}
			return nil

		case 18:
			var v []ExpandedNodeID
			if err := dec.ReadExpandedNodeIDArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeExpandedNodeID, []int32{int32(len(v))}}
			return nil

		case 19:
			var v []StatusCode
			if err := dec.ReadStatusCodeArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeStatusCode, []int32{int32(len(v))}}
			return nil

		case 20:
			var v []QualifiedName
			if err := dec.ReadQualifiedNameArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeQualifiedName, []int32{int32(len(v))}}
			return nil

		case 21:
			var v []LocalizedText
			if err := dec.ReadLocalizedTextArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeLocalizedText, []int32{int32(len(v))}}
			return nil

		case 22:
			var v []interface{}
			if err := dec.ReadObjectArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeExtensionObject, []int32{int32(len(v))}}
			return nil

		case 23:
			var v []*DataValue
			if err := dec.ReadDataValueArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeDataValue, []int32{int32(len(v))}}
			return nil

		case 24:
			var v []*Variant
			if err := dec.ReadVariantArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeVariant, []int32{int32(len(v))}}
			return nil

		case 25:
			var v []*DiagnosticInfo
			if err := dec.ReadDiagnosticInfoArray(&v); err != nil {
				return BadDecodingError
			}
			*value = &Variant{v, VariantTypeDiagnosticInfo, []int32{int32(len(v))}}
			return nil

		default:
			return BadDecodingError
		}
	}

	// TODO: Multidimensional array
	return BadDecodingError
}

// ReadDiagnosticInfo reads a DiagnosticInfo.
func (dec *BinaryDecoder) ReadDiagnosticInfo(value **DiagnosticInfo) error {

	var symbolicID int32 = -1
	var namespaceURI int32 = -1
	var locale int32 = -1
	var localizedText int32 = -1
	var additionalInfo string
	var innerStatusCode StatusCode
	var innerDiagnosticInfo *DiagnosticInfo

	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	if (b & 1) != 0 {
		if err := dec.ReadInt32(&symbolicID); err != nil {
			return BadDecodingError
		}
	}
	if (b & 2) != 0 {
		if err := dec.ReadInt32(&namespaceURI); err != nil {
			return BadDecodingError
		}
	}
	if (b & 8) != 0 {
		if err := dec.ReadInt32(&locale); err != nil {
			return BadDecodingError
		}
	}
	if (b & 4) != 0 {
		if err := dec.ReadInt32(&localizedText); err != nil {
			return BadDecodingError
		}
	}
	if (b & 16) != 0 {
		if err := dec.ReadString(&additionalInfo); err != nil {
			return BadDecodingError
		}
	}
	if (b & 32) != 0 {
		if err := dec.ReadStatusCode(&innerStatusCode); err != nil {
			return BadDecodingError
		}
	}
	if (b & 64) != 0 {
		if err := dec.ReadDiagnosticInfo(&innerDiagnosticInfo); err != nil {
			return BadDecodingError
		}
	}

	*value = NewDiagnosticInfo(namespaceURI, symbolicID, locale, localizedText, additionalInfo, innerStatusCode, innerDiagnosticInfo)
	return nil
}

// ReadBooleanArray reads a bool array.
func (dec *BinaryDecoder) ReadBooleanArray(value *[]bool) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]bool, num)
	for i := range *value {
		if err := dec.ReadBoolean(&(*value)[i]); err != nil {
			return err
		}
	}
	return nil
}

// ReadSByteArray reads a int8 array.
func (dec *BinaryDecoder) ReadSByteArray(value *[]int8) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]int8, num)
	for i := range *value {
		if err := dec.ReadSByte(&(*value)[i]); err != nil {
			return err
		}
	}
	return nil
}

// ReadByteArray reads a byte array.
func (dec *BinaryDecoder) ReadByteArray(value *[]byte) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]byte, num)
	if _, err := io.ReadFull(dec.r, *value); err != nil {
		return BadDecodingError
	}
	return nil
}

// ReadInt16Array reads a int16 array.
func (dec *BinaryDecoder) ReadInt16Array(value *[]int16) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]int16, num)
	for i := range *value {
		if err := dec.ReadInt16(&(*value)[i]); err != nil {
			return err
		}
	}
	return nil

}

// ReadUInt16Array reads a uint16 array.
func (dec *BinaryDecoder) ReadUInt16Array(value *[]uint16) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]uint16, num)
	for i := range *value {
		if err := dec.ReadUInt16(&(*value)[i]); err != nil {
			return err
		}
	}
	return nil
}

// ReadInt32Array reads a int32 array.
func (dec *BinaryDecoder) ReadInt32Array(value *[]int32) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]int32, num)
	for i := range *value {
		if err := dec.ReadInt32(&(*value)[i]); err != nil {
			return err
		}
	}
	return nil
}

// ReadUInt32Array reads a uint32 array.
func (dec *BinaryDecoder) ReadUInt32Array(value *[]uint32) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]uint32, num)
	for i := range *value {
		if err := dec.ReadUInt32(&(*value)[i]); err != nil {
			return err
		}
	}
	return nil
}

// ReadInt64Array reads a int64 array.
func (dec *BinaryDecoder) ReadInt64Array(value *[]int64) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]int64, num)
	for i := range *value {
		if err := dec.ReadInt64(&(*value)[i]); err != nil {
			return err
		}
	}
	return nil
}

// ReadUInt64Array reads a uint64 array.
func (dec *BinaryDecoder) ReadUInt64Array(value *[]uint64) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]uint64, num)
	for i := range *value {
		if err := dec.ReadUInt64(&(*value)[i]); err != nil {
			return err
		}
	}
	return nil

}

// ReadFloatArray reads a float32 array.
func (dec *BinaryDecoder) ReadFloatArray(value *[]float32) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]float32, num)
	for i := range *value {
		if err := dec.ReadFloat(&(*value)[i]); err != nil {
			return err
		}
	}
	return nil

}

// ReadDoubleArray reads a float64 array.
func (dec *BinaryDecoder) ReadDoubleArray(value *[]float64) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]float64, num)
	for i := range *value {
		if err := dec.ReadDouble(&(*value)[i]); err != nil {
			return err
		}
	}
	return nil
}

// ReadStringArray reads a string array.
func (dec *BinaryDecoder) ReadStringArray(value *[]string) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]string, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadString(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadDateTimeArray reads a Time array.
func (dec *BinaryDecoder) ReadDateTimeArray(value *[]time.Time) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]time.Time, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadDateTime(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadGUIDArray reads a UUID array.
func (dec *BinaryDecoder) ReadGUIDArray(value *[]uuid.UUID) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]uuid.UUID, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadGUID(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadByteStringArray reads a ByteString array.
func (dec *BinaryDecoder) ReadByteStringArray(value *[]ByteString) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]ByteString, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadByteString(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadXMLElementArray reads a XmlElement array.
func (dec *BinaryDecoder) ReadXMLElementArray(value *[]XMLElement) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]XMLElement, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadXMLElement(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadNodeIDArray reads a NodeID array.
func (dec *BinaryDecoder) ReadNodeIDArray(value *[]NodeID) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]NodeID, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadNodeID(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadExpandedNodeIDArray reads a ExpandedNodeID array.
func (dec *BinaryDecoder) ReadExpandedNodeIDArray(value *[]ExpandedNodeID) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]ExpandedNodeID, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadExpandedNodeID(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadStatusCodeArray reads a StatusCode array.
func (dec *BinaryDecoder) ReadStatusCodeArray(value *[]StatusCode) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]StatusCode, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadStatusCode(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadQualifiedNameArray reads a QualifiedName array.
func (dec *BinaryDecoder) ReadQualifiedNameArray(value *[]QualifiedName) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]QualifiedName, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadQualifiedName(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadLocalizedTextArray reads a LocalizedText array.
func (dec *BinaryDecoder) ReadLocalizedTextArray(value *[]LocalizedText) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]LocalizedText, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadLocalizedText(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadStructureArray reads a structure array.
// func (dec *BinaryDecoder) ReadStructureArray(value interface{}) error {
// 	rValue := reflect.ValueOf(value).Elem()
// 	var num int32
// 	if err := dec.ReadInt32(&num); err != nil {
// 		return BadDecodingError
// 	}
// 	if num < 0 {
// 		rValue.Set(reflect.Zero(rValue.Type()))
// 		return nil
// 	}
// 	len := int(num)
// 	slc := reflect.MakeSlice(rValue.Type(), len, len)
// 	elemType := rValue.Type().Elem().Elem()
// 	for i := 0; i < len; i++ {
// 		val := reflect.New(elemType)
// 		obj := val.Interface().(Encodable)
// 		obj.Decode(dec)
// 		slc.Index(i).Set(val)
// 	}
// 	rValue.Set(slc)
// 	return nil
// }

// ReadObjectArray reads a object array.
func (dec *BinaryDecoder) ReadObjectArray(value *[]interface{}) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]interface{}, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadObject(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadExtensionObjectArray reads a ExtensionObject array.
func (dec *BinaryDecoder) ReadExtensionObjectArray(value *[]*ExtensionObject) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]*ExtensionObject, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadExtensionObject(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadDataValueArray reads a DataValue array.
func (dec *BinaryDecoder) ReadDataValueArray(value *[]*DataValue) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]*DataValue, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadDataValue(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadVariantArray reads a Variant array.
func (dec *BinaryDecoder) ReadVariantArray(value *[]*Variant) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]*Variant, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadVariant(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}

// ReadDiagnosticInfoArray reads a DiagnosticInfo array.
func (dec *BinaryDecoder) ReadDiagnosticInfoArray(value *[]*DiagnosticInfo) error {
	var num int32
	if err := dec.ReadInt32(&num); err != nil {
		return BadDecodingError
	}
	if num < 0 {
		*value = nil
		return nil
	}
	*value = make([]*DiagnosticInfo, num)
	for i := 0; i < int(num); i++ {
		if err := dec.ReadDiagnosticInfo(&(*value)[i]); err != nil {
			return BadDecodingError
		}
	}
	return nil
}
