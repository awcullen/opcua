// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/google/uuid"
)

var (
	typeToDecoderMap sync.Map
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

type decoderFunc func(*BinaryDecoder, unsafe.Pointer) error

// Decode decodes the value using the UA Binary protocol.
func (dec *BinaryDecoder) Decode(v any) error {
	typ := reflect.TypeOf(v)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	ptr := ((*interfaceHeader)(unsafe.Pointer(&v))).ptr

	// try to retrieve decoder from cache.
	if f, ok := typeToDecoderMap.Load(typ); ok {

		// if found, call it.
		if err := f.(decoderFunc)(dec, ptr); err != nil {
			return err
		}
		return nil
	}

	f, err := getDecoder(typ)
	if err != nil {
		return err
	}
	typeToDecoderMap.Store(typ, f)

	// call the decoder
	if err := f(dec, ptr); err != nil {
		return err
	}
	return nil
}

func getDecoder(typ reflect.Type) (decoderFunc, error) {
	switch typ.Kind() {
	case reflect.Struct:
		switch typ {
		case typeDateTime:
			return getDateTimeDecoder()
		case typeGUID:
			return getGUIDDecoder()
		case typeExpandedNodeID:
			return getExpandedNodeIDDecoder()
		case typeQualifiedName:
			return getQualifiedNameDecoder()
		case typeLocalizedText:
			return getLocalizedTextDecoder()
		case typeDataValue:
			return getDataValueDecoder()
		case typeDiagnosticInfo:
			return getDiagnosticInfoDecoder()
		default:
			return getStructDecoder(typ)
		}
	case reflect.Slice:
		switch elemTyp := typ.Elem(); elemTyp.Kind() {
		case reflect.Uint8:
			return getByteArrayDecoder()
		case reflect.Slice:
			switch elemTyp := elemTyp.Elem(); elemTyp.Kind() {
			case reflect.Slice:
				return get3DSliceDecoder(typ)
			default:
				return get2DSliceDecoder(typ)
			}
		default:
			return getSliceDecoder(typ)
		}
	case reflect.Ptr:
		typ = typ.Elem()
		return getStructPtrDecoder(typ)
	case reflect.Interface:
		switch typ {
		case typeNodeID:
			return getNodeIDDecoder()
		case typeExtensionObject:
			return getExtensionObjectDecoder()
		case typeVariant:
			return getVariantDecoder()
		}
	case reflect.Bool:
		return getBooleanDecoder()
	case reflect.Int8:
		return getSByteDecoder()
	case reflect.Uint8:
		return getByteDecoder()
	case reflect.Int16:
		return getInt16Decoder()
	case reflect.Uint16:
		return getUInt16Decoder()
	case reflect.Int32:
		return getInt32Decoder()
	case reflect.Uint32:
		return getUInt32Decoder()
	case reflect.Int64:
		return getInt64Decoder()
	case reflect.Uint64:
		return getUInt64Decoder()
	case reflect.Float32:
		return getFloatDecoder()
	case reflect.Float64:
		return getDoubleDecoder()
	case reflect.String:
		return getStringDecoder()
	}
	return nil, fmt.Errorf("unsupported type: %s", typ)
}

func getStructDecoder(typ reflect.Type) (decoderFunc, error) {
	decoders := []decoderFunc{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		dec, err := getDecoder(field.Type)
		if err != nil {
			return nil, err
		}
		offset := field.Offset
		decoders = append(decoders, func(buf *BinaryDecoder, p unsafe.Pointer) error {
			return dec(buf, unsafe.Pointer(uintptr(p)+offset))
		})
	}
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		for _, dec := range decoders {
			if err := dec(buf, p); err != nil {
				return err
			}
		}
		return nil
	}, nil
}
func getStructPtrDecoder(typ reflect.Type) (decoderFunc, error) {
	decoders := []decoderFunc{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		dec, err := getDecoder(field.Type)
		if err != nil {
			return nil, err
		}
		offset := field.Offset
		decoders = append(decoders, func(buf *BinaryDecoder, p unsafe.Pointer) error {
			return dec(buf, unsafe.Pointer(uintptr(p)+offset))
		})
	}
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		p2 := unsafe.Pointer(*(**struct{})(p))
		if p2 == nilPtr {
			v := reflect.New(typ)
			reflect.NewAt(v.Type(), p).Elem().Set(v)
			p2 = unsafe.Pointer(*(**struct{})(p))
		}
		for _, dec := range decoders {
			if err := dec(buf, p2); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

func getSliceDecoder(typ reflect.Type) (decoderFunc, error) {
	elem := typ.Elem()
	elemSize := elem.Size()
	elemDecoder, err := getDecoder(elem)
	if err != nil {
		return nil, err
	}
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		hdr := (*sliceHeader)(p)
		var l int32
		if err := buf.ReadInt32(&l); err != nil {
			return err
		}
		len := int(l)
		if len <= 0 {
			hdr.data = unsafe.Pointer(reflect.MakeSlice(typ, 0, 0).Pointer())
			hdr.len = 0
			hdr.cap = 0
			return nil
		}
		hdr.data = unsafe.Pointer(reflect.MakeSlice(typ, len, len).Pointer())
		hdr.len = len
		hdr.cap = len
		//decode first element
		p2 := hdr.data
		if err := elemDecoder(buf, p2); err != nil {
			return err
		}
		//decode remaining elements
		for i := 1; i < len; i++ {
			p2 = unsafe.Pointer(uintptr(p2) + elemSize)
			if err := elemDecoder(buf, p2); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

func get2DSliceDecoder(typ reflect.Type) (decoderFunc, error) {
	// see https://reference.opcfoundation.org/Core/Part6/v105/docs/5.2.5
	panic("Not Implemented")
}

func get3DSliceDecoder(typ reflect.Type) (decoderFunc, error) {
	// see https://reference.opcfoundation.org/Core/Part6/v105/docs/5.2.5
	panic("Not Implemented")
}

func getBooleanDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadBoolean((*bool)(p))
	}, nil
}
func getSByteDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadSByte((*int8)(p))
	}, nil
}
func getByteDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadByte((*uint8)(p))
	}, nil
}
func getInt16Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadInt16((*int16)(p))
	}, nil
}
func getUInt16Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadUInt16((*uint16)(p))
	}, nil
}
func getInt32Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadInt32((*int32)(p))
	}, nil
}
func getUInt32Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadUInt32((*uint32)(p))
	}, nil
}
func getInt64Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadInt64((*int64)(p))
	}, nil
}
func getUInt64Decoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadUInt64((*uint64)(p))
	}, nil
}
func getFloatDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadFloat((*float32)(p))
	}, nil
}
func getDoubleDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadDouble((*float64)(p))
	}, nil
}
func getStringDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadString((*string)(p))
	}, nil
}
func getNodeIDDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadNodeID((*NodeID)(p))
	}, nil
}
func getExpandedNodeIDDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadExpandedNodeID((*ExpandedNodeID)(p))
	}, nil
}
func getDateTimeDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadDateTime((*time.Time)(p))
	}, nil
}
func getGUIDDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadGUID((*uuid.UUID)(p))
	}, nil
}
func getQualifiedNameDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadQualifiedName((*QualifiedName)(p))
	}, nil
}
func getLocalizedTextDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadLocalizedText((*LocalizedText)(p))
	}, nil
}
func getExtensionObjectDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadExtensionObject((*ExtensionObject)(p))
	}, nil
}
func getVariantDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadVariant((*Variant)(p))
	}, nil
}
func getDataValueDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadDataValue((*DataValue)(p))
	}, nil
}
func getDiagnosticInfoDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadDiagnosticInfo((*DiagnosticInfo)(p))
	}, nil
}
func getByteArrayDecoder() (decoderFunc, error) {
	return func(buf *BinaryDecoder, p unsafe.Pointer) error {
		return buf.ReadByteArray((*[]uint8)(p))
	}, nil
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
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = ""
		return nil
	}
	bs := make([]byte, n)
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
	v := uuid.UUID{}
	v[0] = dec.bs[3]
	v[1] = dec.bs[2]
	v[2] = dec.bs[1]
	v[3] = dec.bs[0]
	v[4] = dec.bs[5]
	v[5] = dec.bs[4]
	v[6] = dec.bs[7]
	v[7] = dec.bs[6]
	if _, err := io.ReadFull(dec.r, v[8:]); err != nil {
		return BadDecodingError
	}
	*value = v
	return nil
}

// ReadByteString reads a ByteString.
func (dec *BinaryDecoder) ReadByteString(value *ByteString) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n <= 0 {
		*value = ""
		return nil
	}
	bs := make([]byte, n)
	if _, err := io.ReadFull(dec.r, bs); err != nil {
		return BadDecodingError
	}
	*value = *(*ByteString)(unsafe.Pointer(&bs))
	return nil
}

// ReadXMLElement reads a XMLElement.
func (dec *BinaryDecoder) ReadXMLElement(value *XMLElement) error {
	var s string
	if err := dec.ReadString(&s); err != nil {
		return BadDecodingError
	}
	*value = XMLElement(s)
	return nil
}

var nilGuid = uuid.UUID{}

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
		if id == 0 {
			*value = nil
			return nil
		}
		*value = NewNodeIDNumeric(uint16(0), uint32(id))
		return nil

	case 0x01:
		var ns byte
		var id uint16
		if err := dec.ReadByte(&ns); err != nil {
			return BadDecodingError
		}
		if err := dec.ReadUInt16(&id); err != nil {
			return BadDecodingError
		}
		*value = NewNodeIDNumeric(uint16(ns), uint32(id))
		return nil

	case 0x02:
		var ns uint16
		var id uint32
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		if err := dec.ReadUInt32(&id); err != nil {
			return BadDecodingError
		}
		*value = NewNodeIDNumeric(ns, uint32(id))
		return nil

	case 0x03:
		var ns uint16
		var id string
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		if err := dec.ReadString(&id); err != nil {
			return BadDecodingError
		}
		if ns == 0 && id == "" {
			*value = nil
			return nil
		}
		*value = NewNodeIDString(ns, id)
		return nil

	case 0x04:
		var ns uint16
		var id uuid.UUID
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		if err := dec.ReadGUID(&id); err != nil {
			return BadDecodingError
		}
		if ns == 0 && id == nilGuid {
			*value = nil
			return nil
		}
		*value = NewNodeIDGUID(ns, id)
		return nil

	case 0x05:
		var ns uint16
		var id ByteString
		if err := dec.ReadUInt16(&ns); err != nil {
			return BadDecodingError
		}
		if err := dec.ReadByteString(&id); err != nil {
			return BadDecodingError
		}
		if ns == 0 && id == "" {
			*value = nil
			return nil
		}
		*value = NewNodeIDOpaque(ns, id)
		return nil

	default:
		return BadDecodingError
	}
}

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
		if id == 0 {
			n = nil
		} else {
			n = NewNodeIDNumeric(uint16(0), uint32(id))
		}
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
	var (
		ns   uint16
		name string
	)
	if err := dec.ReadUInt16(&ns); err != nil {
		return BadDecodingError
	}
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
	)
	var b byte
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

// ReadExtensionObject reads an Extensionobject.
func (dec *BinaryDecoder) ReadExtensionObject(value *ExtensionObject) error {
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
		return nil
	case 0x01:
		id := ToExpandedNodeID(nodeID, dec.ec.NamespaceURIs())
		// lookup type
		typ, ok := FindTypeForBinaryEncodingID(id)
		if ok {
			var unused int32
			if err := dec.ReadInt32(&unused); err != nil {
				return BadDecodingError
			}
			obj := reflect.New(typ).Elem().Interface() // TODO: decide if ptr or struct
			if err := dec.Decode(obj); err != nil {
				return BadDecodingError
			}
			*value = obj
			return nil
		}
		var body []byte
		err := dec.ReadByteArray(&body)
		if err != nil {
			return BadDecodingError
		}
		return nil
	case 0x02:
		var body XMLElement
		err := dec.ReadXMLElement(&body)
		if err != nil {
			return BadDecodingError
		}
		return nil
	default:
		return BadDecodingError
	}
}

// ReadDataValue reads a DataValue.
func (dec *BinaryDecoder) ReadDataValue(value *DataValue) error {
	var (
		v                 Variant
		statusCode        StatusCode
		sourceTimestamp   time.Time
		sourcePicoseconds uint16
		serverTimestamp   time.Time
		serverPicoseconds uint16
		err               error
	)
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	if (b & 1) != 0 {
		if err := dec.ReadVariant(&v); err != nil {
			// return BadDecodingError
			statusCode = BadDataTypeIDUnknown
		}
	}
	if (b&2) != 0 && statusCode == 0 {
		if err := dec.ReadStatusCode(&statusCode); err != nil {
			return BadDecodingError
		}
	}
	if (b & 4) != 0 {
		if err = dec.ReadDateTime(&sourceTimestamp); err != nil {
			return BadDecodingError
		}
	}
	if (b & 16) != 0 {
		if err := dec.ReadUInt16(&sourcePicoseconds); err != nil {
			return BadDecodingError
		}
	}
	if (b & 8) != 0 {
		if err = dec.ReadDateTime(&serverTimestamp); err != nil {
			return BadDecodingError
		}
	}
	if (b & 32) != 0 {
		if err := dec.ReadUInt16(&serverPicoseconds); err != nil {
			return BadDecodingError
		}
	}
	*value = DataValue{v, statusCode, sourceTimestamp, sourcePicoseconds, serverTimestamp, serverPicoseconds}
	return nil
}

// ReadVariant reads a Variant.
func (dec *BinaryDecoder) ReadVariant(value *Variant) error {
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}

	// If scalar value
	if (b & VariantTypeArray) == 0 {
		switch b & 0x3F {
		case VariantTypeNull:
			*value = nil
			return nil

		case VariantTypeBoolean:
			var v bool
			if err := dec.ReadBoolean(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeSByte:
			var v int8
			if err := dec.ReadSByte(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeByte:
			var v byte
			if err := dec.ReadByte(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt16:
			var v int16
			if err := dec.ReadInt16(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt16:
			var v uint16
			if err := dec.ReadUInt16(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt32:
			var v int32
			if err := dec.ReadInt32(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt32:
			var v uint32
			if err := dec.ReadUInt32(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt64:
			var v int64
			if err := dec.ReadInt64(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt64:
			var v uint64
			if err := dec.ReadUInt64(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeFloat:
			var v float32
			if err := dec.ReadFloat(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDouble:
			var v float64
			if err := dec.ReadDouble(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeString:
			var v string
			if err := dec.ReadString(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDateTime:
			var v time.Time
			if err := dec.ReadDateTime(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeGUID:
			var v uuid.UUID
			if err := dec.ReadGUID(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeByteString:
			var v ByteString
			if err := dec.ReadByteString(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeXMLElement:
			var v XMLElement
			if err := dec.ReadXMLElement(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeNodeID:
			var v NodeID
			if err := dec.ReadNodeID(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeExpandedNodeID:
			var v ExpandedNodeID
			if err := dec.ReadExpandedNodeID(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeStatusCode:
			var v StatusCode
			if err := dec.ReadStatusCode(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeQualifiedName:
			var v QualifiedName
			if err := dec.ReadQualifiedName(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeLocalizedText:
			var v LocalizedText
			if err := dec.ReadLocalizedText(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeExtensionObject:
			var v ExtensionObject
			if err := dec.ReadExtensionObject(&v); err != nil {
				return err
			}
			*value = v
			return nil

		case VariantTypeDataValue:
			var v DataValue
			if err := dec.ReadDataValue(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeVariant:
			var v Variant
			if err := dec.ReadVariant(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDiagnosticInfo:
			var v DiagnosticInfo
			if err := dec.ReadDiagnosticInfo(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		default:
			return BadDecodingError
		}
	}

	// if single dimension array
	if (b & VariantTypeMultiDimensionArray) == 0 {
		switch b & 0x3F {
		case VariantTypeNull:
			*value = nil
			return nil

		case VariantTypeBoolean:
			var v []bool
			if err := dec.ReadBooleanArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeSByte:
			var v []int8
			if err := dec.ReadSByteArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeByte:
			var v []byte
			if err := dec.ReadByteArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt16:
			var v []int16
			if err := dec.ReadInt16Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt16:
			var v []uint16
			if err := dec.ReadUInt16Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt32:
			var v []int32
			if err := dec.ReadInt32Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt32:
			var v []uint32
			if err := dec.ReadUInt32Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeInt64:
			var v []int64
			if err := dec.ReadInt64Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeUInt64:
			var v []uint64
			if err := dec.ReadUInt64Array(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeFloat:
			var v []float32
			if err := dec.ReadFloatArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDouble:
			var v []float64
			if err := dec.ReadDoubleArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeString:
			var v []string
			if err := dec.ReadStringArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDateTime:
			var v []time.Time
			if err := dec.ReadDateTimeArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeGUID:
			var v []uuid.UUID
			if err := dec.ReadGUIDArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeByteString:
			var v []ByteString
			if err := dec.ReadByteStringArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeXMLElement:
			var v []XMLElement
			if err := dec.ReadXMLElementArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeNodeID:
			var v []NodeID
			if err := dec.ReadNodeIDArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeExpandedNodeID:
			var v []ExpandedNodeID
			if err := dec.ReadExpandedNodeIDArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeStatusCode:
			var v []StatusCode
			if err := dec.ReadStatusCodeArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeQualifiedName:
			var v []QualifiedName
			if err := dec.ReadQualifiedNameArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeLocalizedText:
			var v []LocalizedText
			if err := dec.ReadLocalizedTextArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeExtensionObject:
			var v []ExtensionObject
			if err := dec.ReadExtensionObjectArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDataValue:
			var v []DataValue
			if err := dec.ReadDataValueArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeVariant:
			var v []Variant
			if err := dec.ReadVariantArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		case VariantTypeDiagnosticInfo:
			var v []DiagnosticInfo
			if err := dec.ReadDiagnosticInfoArray(&v); err != nil {
				return BadDecodingError
			}
			*value = v
			return nil

		default:
			return BadDecodingError
		}
	}

	// Multidimensional array
	switch b & 0x3F {
	case VariantTypeNull:
		*value = nil
		return nil
	case VariantTypeBoolean:
		var vals []bool
		if err := dec.ReadBooleanArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]bool, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]bool, dims[0])
			for i := range res {
				res[i] = make([][]bool, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeSByte:
		var vals []int8
		if err := dec.ReadSByteArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]int8, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]int8, dims[0])
			for i := range res {
				res[i] = make([][]int8, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeByte:
		var vals []byte
		if err := dec.ReadByteArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]byte, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]byte, dims[0])
			for i := range res {
				res[i] = make([][]byte, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeInt16:
		var vals []int16
		if err := dec.ReadInt16Array(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]int16, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]int16, dims[0])
			for i := range res {
				res[i] = make([][]int16, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeUInt16:
		var vals []uint16
		if err := dec.ReadUInt16Array(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]uint16, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]uint16, dims[0])
			for i := range res {
				res[i] = make([][]uint16, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeInt32:
		var vals []int32
		if err := dec.ReadInt32Array(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]int32, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]int32, dims[0])
			for i := range res {
				res[i] = make([][]int32, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeUInt32:
		var vals []uint32
		if err := dec.ReadUInt32Array(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]uint32, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]uint32, dims[0])
			for i := range res {
				res[i] = make([][]uint32, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeInt64:
		var vals []int64
		if err := dec.ReadInt64Array(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]int64, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]int64, dims[0])
			for i := range res {
				res[i] = make([][]int64, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeUInt64:
		var vals []uint64
		if err := dec.ReadUInt64Array(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]uint64, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]uint64, dims[0])
			for i := range res {
				res[i] = make([][]uint64, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeFloat:
		var vals []float32
		if err := dec.ReadFloatArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]float32, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]float32, dims[0])
			for i := range res {
				res[i] = make([][]float32, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeDouble:
		var vals []float64
		if err := dec.ReadDoubleArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]float64, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]float64, dims[0])
			for i := range res {
				res[i] = make([][]float64, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeString:
		var vals []string
		if err := dec.ReadStringArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]string, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]string, dims[0])
			for i := range res {
				res[i] = make([][]string, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeDateTime:
		var vals []time.Time
		if err := dec.ReadDateTimeArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]time.Time, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]time.Time, dims[0])
			for i := range res {
				res[i] = make([][]time.Time, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeGUID:
		var vals []uuid.UUID
		if err := dec.ReadGUIDArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]uuid.UUID, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]uuid.UUID, dims[0])
			for i := range res {
				res[i] = make([][]uuid.UUID, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeByteString:
		var vals []ByteString
		if err := dec.ReadByteStringArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]ByteString, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]ByteString, dims[0])
			for i := range res {
				res[i] = make([][]ByteString, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeXMLElement:
		var vals []XMLElement
		if err := dec.ReadXMLElementArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]XMLElement, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]XMLElement, dims[0])
			for i := range res {
				res[i] = make([][]XMLElement, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeNodeID:
		var vals []NodeID
		if err := dec.ReadNodeIDArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]NodeID, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]NodeID, dims[0])
			for i := range res {
				res[i] = make([][]NodeID, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeExpandedNodeID:
		var vals []ExpandedNodeID
		if err := dec.ReadExpandedNodeIDArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]ExpandedNodeID, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]ExpandedNodeID, dims[0])
			for i := range res {
				res[i] = make([][]ExpandedNodeID, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeStatusCode:
		var vals []StatusCode
		if err := dec.ReadStatusCodeArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]StatusCode, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]StatusCode, dims[0])
			for i := range res {
				res[i] = make([][]StatusCode, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeQualifiedName:
		var vals []QualifiedName
		if err := dec.ReadQualifiedNameArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]QualifiedName, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]QualifiedName, dims[0])
			for i := range res {
				res[i] = make([][]QualifiedName, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeLocalizedText:
		var vals []LocalizedText
		if err := dec.ReadLocalizedTextArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]LocalizedText, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]LocalizedText, dims[0])
			for i := range res {
				res[i] = make([][]LocalizedText, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeExtensionObject:
		var vals []ExtensionObject
		if err := dec.ReadExtensionObjectArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]ExtensionObject, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]ExtensionObject, dims[0])
			for i := range res {
				res[i] = make([][]ExtensionObject, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeDataValue:
		var vals []DataValue
		if err := dec.ReadDataValueArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]DataValue, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]DataValue, dims[0])
			for i := range res {
				res[i] = make([][]DataValue, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeVariant:
		var vals []Variant
		if err := dec.ReadVariantArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]Variant, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]Variant, dims[0])
			for i := range res {
				res[i] = make([][]Variant, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	case VariantTypeDiagnosticInfo:
		var vals []DiagnosticInfo
		if err := dec.ReadDiagnosticInfoArray(&vals); err != nil {
			return BadDecodingError
		}
		var dims []int32
		if err := dec.ReadInt32Array(&dims); err != nil {
			return BadDecodingError
		}
		if len(dims) == 2 {
			res := make([][]DiagnosticInfo, dims[0])
			for i := range res {
				res[i], vals = vals[:dims[1]], vals[dims[1]:]
			}
			*value = res
			return nil
		}
		if len(dims) == 3 {
			res := make([][][]DiagnosticInfo, dims[0])
			for i := range res {
				res[i] = make([][]DiagnosticInfo, dims[1])
				for j := range res[i] {
					res[i][j], vals = vals[:dims[2]], vals[dims[2]:]
				}
			}
			*value = res
			return nil
		}
		return BadDecodingError

	default:
		return BadDecodingError
	}
}

// split recursively creates a multi-dimensional slice from a set of values
// and some given dimensions.
// func split(level, i, j int, dims []int, vals reflect.Value) reflect.Value {
// 	if level == len(dims)-1 {
// 		a := vals.Slice(i, j)
// 		return a
// 	}

// 	// split next level
// 	var elems []reflect.Value
// 	if vals.Len() > 0 {
// 		step := (j - i) / dims[level]
// 		for ; i < j; i += step {
// 			elems = append(elems, split(level+1, i, i+step, dims, vals))
// 		}
// 	} else {
// 		for k := 0; k < dims[level]; k++ {
// 			elems = append(elems, split(level+1, 0, 0, dims, vals))
// 		}
// 	}

// 	// now construct the typed slice, i.e. [](type of inner slice)
// 	innerT := elems[0].Type()
// 	a := reflect.MakeSlice(reflect.SliceOf(innerT), len(elems), len(elems))
// 	for k := range elems {
// 		a.Index(k).Set(elems[k])
// 	}
// 	return a
// }

// ReadDiagnosticInfo reads a DiagnosticInfo.
func (dec *BinaryDecoder) ReadDiagnosticInfo(value *DiagnosticInfo) error {
	result := DiagnosticInfo{}
	var b byte
	if err := dec.ReadByte(&b); err != nil {
		return BadDecodingError
	}
	if (b & 1) != 0 {
		if err := dec.ReadInt32(result.SymbolicID); err != nil {
			return BadDecodingError
		}
	}
	if (b & 2) != 0 {
		if err := dec.ReadInt32(result.NamespaceURI); err != nil {
			return BadDecodingError
		}
	}
	if (b & 8) != 0 {
		if err := dec.ReadInt32(result.Locale); err != nil {
			return BadDecodingError
		}
	}
	if (b & 4) != 0 {
		if err := dec.ReadInt32(result.LocalizedText); err != nil {
			return BadDecodingError
		}
	}
	if (b & 16) != 0 {
		if err := dec.ReadString(result.AdditionalInfo); err != nil {
			return BadDecodingError
		}
	}
	if (b & 32) != 0 {
		if err := dec.ReadStatusCode(result.InnerStatusCode); err != nil {
			return BadDecodingError
		}
	}
	if (b & 64) != 0 {
		if err := dec.ReadDiagnosticInfo(result.InnerDiagnosticInfo); err != nil {
			return BadDecodingError
		}
	}
	*value = result
	return nil
}

// ReadBooleanArray reads a bool array.
func (dec *BinaryDecoder) ReadBooleanArray(value *[]bool) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]bool, n)
	for i := range temp {
		if err := dec.ReadBoolean(&temp[i]); err != nil {
			return err
		}
	}
	*value = temp
	return nil
}

// ReadSByteArray reads a int8 array.
func (dec *BinaryDecoder) ReadSByteArray(value *[]int8) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]int8, n)
	for i := range temp {
		if err := dec.ReadSByte(&temp[i]); err != nil {
			return err
		}
	}
	*value = temp
	return nil
}

// ReadByteArray reads a byte array.
func (dec *BinaryDecoder) ReadByteArray(value *[]byte) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]byte, n)
	if _, err := io.ReadFull(dec.r, temp); err != nil {
		return err
	}
	*value = temp
	return nil
}

// ReadInt16Array reads a int16 array.
func (dec *BinaryDecoder) ReadInt16Array(value *[]int16) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]int16, n)
	for i := range temp {
		if err := dec.ReadInt16(&temp[i]); err != nil {
			return err
		}
	}
	*value = temp
	return nil
}

// ReadUInt16Array reads a uint16 array.
func (dec *BinaryDecoder) ReadUInt16Array(value *[]uint16) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]uint16, n)
	for i := range temp {
		if err := dec.ReadUInt16(&temp[i]); err != nil {
			return err
		}
	}
	*value = temp
	return nil
}

// ReadInt32Array reads a int32 array.
func (dec *BinaryDecoder) ReadInt32Array(value *[]int32) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]int32, n)
	for i := range temp {
		if err := dec.ReadInt32(&temp[i]); err != nil {
			return err
		}
	}
	*value = temp
	return nil
}

// ReadUInt32Array reads a uint32 array.
func (dec *BinaryDecoder) ReadUInt32Array(value *[]uint32) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]uint32, n)
	for i := range temp {
		if err := dec.ReadUInt32(&temp[i]); err != nil {
			return err
		}
	}
	*value = temp
	return nil
}

// ReadInt64Array reads a int64 array.
func (dec *BinaryDecoder) ReadInt64Array(value *[]int64) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]int64, n)
	for i := range temp {
		if err := dec.ReadInt64(&temp[i]); err != nil {
			return err
		}
	}
	*value = temp
	return nil
}

// ReadUInt64Array reads a uint64 array.
func (dec *BinaryDecoder) ReadUInt64Array(value *[]uint64) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]uint64, n)
	for i := range temp {
		if err := dec.ReadUInt64(&temp[i]); err != nil {
			return err
		}
	}
	*value = temp
	return nil
}

// ReadFloatArray reads a float32 array.
func (dec *BinaryDecoder) ReadFloatArray(value *[]float32) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]float32, n)
	for i := range temp {
		if err := dec.ReadFloat(&temp[i]); err != nil {
			return err
		}
	}
	*value = temp
	return nil
}

// ReadDoubleArray reads a float64 array.
func (dec *BinaryDecoder) ReadDoubleArray(value *[]float64) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]float64, n)
	for i := range temp {
		if err := dec.ReadDouble(&temp[i]); err != nil {
			return err
		}
	}
	*value = temp
	return nil
}

// ReadStringArray reads a string array.
func (dec *BinaryDecoder) ReadStringArray(value *[]string) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]string, n)
	for i := range temp {
		if err := dec.ReadString(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadDateTimeArray reads a Time array.
func (dec *BinaryDecoder) ReadDateTimeArray(value *[]time.Time) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]time.Time, n)
	for i := range temp {
		if err := dec.ReadDateTime(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadGUIDArray reads a UUID array.
func (dec *BinaryDecoder) ReadGUIDArray(value *[]uuid.UUID) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]uuid.UUID, n)
	for i := range temp {
		if err := dec.ReadGUID(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadByteStringArray reads a ByteString array.
func (dec *BinaryDecoder) ReadByteStringArray(value *[]ByteString) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]ByteString, n)
	for i := 0; i < len(temp); i++ {
		if err := dec.ReadByteString(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadXMLElementArray reads a XMLElement array.
func (dec *BinaryDecoder) ReadXMLElementArray(value *[]XMLElement) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]XMLElement, n)
	for i := 0; i < len(temp); i++ {
		if err := dec.ReadXMLElement(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadNodeIDArray reads a NodeID array.
func (dec *BinaryDecoder) ReadNodeIDArray(value *[]NodeID) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]NodeID, n)
	for i := range temp {
		if err := dec.ReadNodeID(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadExpandedNodeIDArray reads a ExpandedNodeID array.
func (dec *BinaryDecoder) ReadExpandedNodeIDArray(value *[]ExpandedNodeID) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]ExpandedNodeID, n)
	for i := range temp {
		if err := dec.ReadExpandedNodeID(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadStatusCodeArray reads a StatusCode array.
func (dec *BinaryDecoder) ReadStatusCodeArray(value *[]StatusCode) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]StatusCode, n)
	for i := range temp {
		if err := dec.ReadStatusCode(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadQualifiedNameArray reads a QualifiedName array.
func (dec *BinaryDecoder) ReadQualifiedNameArray(value *[]QualifiedName) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]QualifiedName, n)
	for i := range temp {
		if err := dec.ReadQualifiedName(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadLocalizedTextArray reads a LocalizedText array.
func (dec *BinaryDecoder) ReadLocalizedTextArray(value *[]LocalizedText) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]LocalizedText, n)
	for i := range temp {
		if err := dec.ReadLocalizedText(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadExtensionObjectArray reads a ExtensionObject array.
func (dec *BinaryDecoder) ReadExtensionObjectArray(value *[]ExtensionObject) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]ExtensionObject, n)
	for i := range temp {
		if err := dec.ReadExtensionObject(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadDataValueArray reads a DataValue array.
func (dec *BinaryDecoder) ReadDataValueArray(value *[]DataValue) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]DataValue, n)
	for i := 0; i < len(temp); i++ {
		if err := dec.ReadDataValue(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadVariantArray reads a Variant array.
func (dec *BinaryDecoder) ReadVariantArray(value *[]Variant) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]Variant, n)
	for i := 0; i < len(temp); i++ {
		if err := dec.ReadVariant(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}

// ReadDiagnosticInfoArray reads a DiagnosticInfo array.
func (dec *BinaryDecoder) ReadDiagnosticInfoArray(value *[]DiagnosticInfo) error {
	var n int32
	if err := dec.ReadInt32(&n); err != nil {
		return BadDecodingError
	}
	if n < 0 {
		*value = nil
		return nil
	}
	temp := make([]DiagnosticInfo, n)
	for i := 0; i < len(temp); i++ {
		if err := dec.ReadDiagnosticInfo(&temp[i]); err != nil {
			return BadDecodingError
		}
	}
	*value = temp
	return nil
}
