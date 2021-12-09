package ua

import (
	"encoding/xml"
	"time"
)

// UANodeSet supports reading UANodeSet from xml.
type UANodeSet struct {
	NamespaceUris []string      `xml:"NamespaceUris>Uri,omitempty"`
	ServerUris    []string      `xml:"ServerUris>Uri,omitempty"`
	Aliases       []Alias       `xml:"Aliases>Alias,omitempty"`
	Models        []interface{} `xml:"Models>Model,omitempty"`
	Extensions    []interface{} `xml:"Extensions>Extension,omitempty"`
	Nodes         []UANode      `xml:",any,omitempty"`
	LastModified  time.Time     `xml:"LastModified,attr"`
}

// UANode supports reading UANodeSet from xml.
type UANode struct {
	XMLName       xml.Name
	DisplayName   UALocalizedText `xml:"DisplayName"`
	Description   UALocalizedText `xml:"Description"`
	References    []*UAReference  `xml:"References>Reference,omitempty"`
	Extensions    []interface{}   `xml:"Extensions>Extension,omitempty"`
	NodeID        string          `xml:"NodeId,attr"`
	BrowseName    string          `xml:"BrowseName,attr"`
	WriteMask     uint32          `xml:"WriteMask,attr"`
	UserWriteMask uint32          `xml:"UserWriteMask,attr"`
	// UAType
	IsAbstract bool `xml:"IsAbstract,attr"`
	// UAObjectType
	// UAVariableType
	DataType        string `xml:"DataType,attr"`
	ValueRank       string `xml:"ValueRank,attr"`
	ArrayDimensions string `xml:"ArrayDimensions,attr"`
	// UADataType
	Definition *UADataTypeDefinition `xml:"Definition"`
	// UAReferenceType
	InverseName string `xml:"InverseName"`
	Symmetric   bool   `xml:"Symmetric,attr"`
	// UAObject
	EventNotifier uint8 `xml:"EventNotifier,attr"`
	// UAVariable
	Value                   UAVariant `xml:"Value"`
	AccessLevel             string    `xml:"AccessLevel,attr"`
	UserAccessLevel         string    `xml:"UserAccessLevel,attr"`
	MinimumSamplingInterval float64   `xml:"MinimumSamplingInterval,attr"`
	Historizing             bool      `xml:"Historizing,attr"`
	// UAMethod
	Executable     string `xml:"Executable,attr"`
	UserExecutable string `xml:"UserExecutable,attr"`
	// UAView
	ContainsNoLoops bool `xml:"ContainsNoLoops,attr"`
}

// Alias supports reading UANodeSet from xml.
type Alias struct {
	Alias  string `xml:"Alias,attr"`
	NodeID string `xml:",innerxml"`
}

// UAReference supports reading UANodeSet from xml.
type UAReference struct {
	ReferenceType string `xml:"ReferenceType,attr"`
	IsForward     string `xml:"IsForward,attr"`
	TargetNodeID  string `xml:",innerxml"`
}

// UADataTypeDefinition supports reading UANodeSet from xml.
type UADataTypeDefinition struct {
	Field    []UADataTypeField
	Name     string `xml:"Name,attr"`
	BaseType string `xml:"BaseType,attr"`
	IsUnion  bool   `xml:"IsUnion,attr"`
}

// UADataTypeField supports reading UANodeSet from xml.
type UADataTypeField struct {
	Description string               `xml:"Description"`
	Definition  UADataTypeDefinition `xml:"Definition"`
	Name        string               `xml:"Name,attr"`
	DataType    string               `xml:"DataType,attr"`
	ValueRank   int                  `xml:"ValueRank,attr"`
	Value       int                  `xml:"Value,attr"`
	IsOptional  bool                 `xml:"IsOptional,attr"`
}

// ListOfBoolean supports reading UANodeSet from xml.
type ListOfBoolean struct {
	List []bool `xml:"Boolean,omitempty"`
}

// ListOfSByte supports reading UANodeSet from xml.
type ListOfSByte struct {
	List []int8 `xml:"SByte,omitempty"`
}

// ListOfByte supports reading UANodeSet from xml.
type ListOfByte struct {
	List []uint16 `xml:"Byte,omitempty"` //bugfix: xml.Encoding can't directly decode into []byte.
}

// ListOfInt16 supports reading UANodeSet from xml.
type ListOfInt16 struct {
	List []int16 `xml:"Int16,omitempty"`
}

// ListOfUInt16 supports reading UANodeSet from xml.
type ListOfUInt16 struct {
	List []uint16 `xml:"UInt16,omitempty"`
}

// ListOfInt32 supports reading UANodeSet from xml.
type ListOfInt32 struct {
	List []int32 `xml:"Int32,omitempty"`
}

// ListOfUInt32 supports reading UANodeSet from xml.
type ListOfUInt32 struct {
	List []uint32 `xml:"UInt32,omitempty"`
}

// ListOfInt64 supports reading UANodeSet from xml.
type ListOfInt64 struct {
	List []int64 `xml:"Int64,omitempty"`
}

// ListOfUInt64 supports reading UANodeSet from xml.
type ListOfUInt64 struct {
	List []uint64 `xml:"UInt64,omitempty"`
}

// ListOfFloat supports reading UANodeSet from xml.
type ListOfFloat struct {
	List []float32 `xml:"Float,omitempty"`
}

// ListOfDouble supports reading UANodeSet from xml.
type ListOfDouble struct {
	List []float64 `xml:"Double,omitempty"`
}

// ListOfString supports reading UANodeSet from xml.
type ListOfString struct {
	List []string `xml:"String,omitempty"`
}

// ListOfDateTime supports reading UANodeSet from xml.
type ListOfDateTime struct {
	List []time.Time `xml:"DateTime,omitempty"`
}

// ListOfByteString supports reading UANodeSet from xml.
type ListOfByteString struct {
	List []ByteString `xml:"ByteString,omitempty"`
}

// UAXMLElement supports reading UANodeSet from xml.
type UAXMLElement struct {
	InnerXML string `xml:",innerxml"`
}

// ListOfXMLElement supports reading UANodeSet from xml.
type ListOfXMLElement struct {
	List []*UAXMLElement `xml:"XmlElement"`
}

// UAGUID supports reading UANodeSet from xml.
type UAGUID struct {
	String string `xml:"String"`
}

// ListOfGUID supports reading UANodeSet from xml.
type ListOfGUID struct {
	List []*string `xml:"Guid>String,omitempty"`
}

// UALocalizedText supports reading UANodeSet from xml.
type UALocalizedText struct {
	Text    string `xml:"Text"`
	Locale  string `xml:"Locale"`
	Content string `xml:",innerxml"`
}

// ListOfLocalizedText supports reading UANodeSet from xml.
type ListOfLocalizedText struct {
	List []UALocalizedText `xml:"LocalizedText,omitempty"`
}

// UAQualifiedName supports reading UANodeSet from xml.
type UAQualifiedName struct {
	NamespaceIndex uint16 `xml:"NamespaceIndex"`
	Name           string `xml:"Name"`
}

// ListOfQualifiedName supports reading UANodeSet from xml.
type ListOfQualifiedName struct {
	List []UAQualifiedName `xml:"QualifiedName,omitempty"`
}

// UAArgument supports reading UANodeSet from xml.
type UAArgument struct {
	Name            string          `xml:"Name"`
	DataType        string          `xml:"DataType>Identifier"`
	ValueRank       string          `xml:"ValueRank"`
	ArrayDimensions string          `xml:"ArrayDimensions"`
	Description     UALocalizedText `xml:"Description"`
}

// UAEUInformation supports reading UANodeSet from xml.
type UAEUInformation struct {
	NamespaceURI string          `xml:"NamespaceUri"`
	UnitID       int32           `xml:"UnitId"`
	DisplayName  UALocalizedText `xml:"DisplayName"`
	Description  UALocalizedText `xml:"Description"`
}

// UARange supports reading UANodeSet from xml.
type UARange struct {
	Low  float64 `xml:"Low"`
	High float64 `xml:"High"`
}

// UAEnumValueType supports reading UANodeSet from xml.
type UAEnumValueType struct {
	Value       int64           `xml:"Value"`
	DisplayName UALocalizedText `xml:"DisplayName"`
	Description UALocalizedText `xml:"Description"`
}

// UAExtensionObject supports reading UANodeSet from xml.
type UAExtensionObject struct {
	TypeID        string           `xml:"TypeId>Identifier"`
	Argument      *UAArgument      `xml:"Body>Argument"`
	EUInformation *UAEUInformation `xml:"Body>EUInformation"`
	Range         *UARange         `xml:"Body>Range"`
	EnumValueType *UAEnumValueType `xml:"Body>EnumValueType"`
}

// ListOfExtensionObject supports reading UANodeSet from xml.
type ListOfExtensionObject struct {
	List []UAExtensionObject `xml:"ExtensionObject,omitempty"`
}

// UANodeID supports reading UANodeSet from xml.
type UANodeID struct {
	Identifier string `xml:"Identifier"`
}

// UAExpandedNodeID supports reading UANodeSet from xml.
type UAExpandedNodeID struct {
	Identifier string `xml:"Identifier"`
}

// UAVariant supports reading UANodeSet from xml.
type UAVariant struct {
	XMLName         xml.Name
	Bool            *bool              `xml:"Boolean"`
	Byte            *uint8             `xml:"Byte"`
	UInt16          *uint16            `xml:"UInt16"`
	UInt32          *uint32            `xml:"UInt32"`
	UInt64          *uint64            `xml:"UInt64"`
	SByte           *int8              `xml:"SByte"`
	Int16           *int16             `xml:"Int16"`
	Int32           *int32             `xml:"Int32"`
	Int64           *int64             `xml:"Int64"`
	Float           *float32           `xml:"Float"`
	Double          *float64           `xml:"Double"`
	String          *string            `xml:"String"`
	ByteString      *ByteString        `xml:"ByteString"`
	XMLElement      *UAXMLElement      `xml:"XmlElement"`
	DateTime        *time.Time         `xml:"DateTime"`
	GUID            *UAGUID            `xml:"Guid"`
	LocalizedText   *UALocalizedText   `xml:"LocalizedText"`
	QualifiedName   *UAQualifiedName   `xml:"QualifiedName"`
	ExtensionObject *UAExtensionObject `xml:"ExtensionObject"`
	NodeID          *UANodeID          `xml:"NodeId"`
	ExpandedNodeID  *UAExpandedNodeID  `xml:"ExpandedNodeId"`

	ListOfBoolean         *ListOfBoolean         `xml:"ListOfBoolean"`
	ListOfByte            *ListOfByte            `xml:"ListOfByte"`
	ListOfUInt16          *ListOfUInt16          `xml:"ListOfUInt16"`
	ListOfUInt32          *ListOfUInt32          `xml:"ListOfUInt32"`
	ListOfUInt64          *ListOfUInt64          `xml:"ListOfUInt64"`
	ListOfSByte           *ListOfSByte           `xml:"ListOfSByte"`
	ListOfInt16           *ListOfInt16           `xml:"ListOfInt16"`
	ListOfInt32           *ListOfInt32           `xml:"ListOfInt32"`
	ListOfInt64           *ListOfInt64           `xml:"ListOfInt64"`
	ListOfFloat           *ListOfFloat           `xml:"ListOfFloat"`
	ListOfDouble          *ListOfDouble          `xml:"ListOfDouble"`
	ListOfString          *ListOfString          `xml:"ListOfString"`
	ListOfByteString      *ListOfByteString      `xml:"ListOfByteString"`
	ListOfXMLElement      *ListOfXMLElement      `xml:"ListOfXmlElement"`
	ListOfDateTime        *ListOfDateTime        `xml:"ListOfDateTime"`
	ListOfGUID            *ListOfGUID            `xml:"ListOfGuid"`
	ListOfLocalizedText   *ListOfLocalizedText   `xml:"ListOfLocalizedText"`
	ListOfQualifiedName   *ListOfQualifiedName   `xml:"ListOfQualifiedName"`
	ListOfExtensionObject *ListOfExtensionObject `xml:"ListOfExtensionObject"`
	ListOfVariant         *ListOfVariant         `xml:"ListOfVariant"`
}

// UAVariant2 supports reading UANodeSet from xml.
type UAVariant2 struct {
	XMLName  xml.Name
	InnerXML string `xml:",innerxml"`
}

// ListOfVariant supports reading UANodeSet from xml.
type ListOfVariant struct {
	List []UAVariant2 `xml:",any,omitempty"`
}
