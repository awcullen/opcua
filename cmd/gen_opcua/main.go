// Copyright 2021 Converter Systems LLC. All rights reserved.

// gen_opcua is a tool to generate the standard types, nodeids, and status codes from the schema provided by the OPC Foundation.
package main

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"text/tabwriter"
	"text/template"
)

var (
	in, out        string
	builtInTypeMap = map[string]string{
		"Boolean":         "bool",
		"Byte":            "uint8",
		"SByte":           "int8",
		"Int16":           "int16",
		"Int32":           "int32",
		"Int64":           "int64",
		"UInt16":          "uint16",
		"UInt32":          "uint32",
		"UInt64":          "uint64",
		"Float":           "float32",
		"Double":          "float64",
		"String":          "string",
		"DateTime":        "time.Time",
		"GUID":            "uuid.UUID",
		"ByteString":      "ByteString",
		"XmlElement":      "XmlElement",
		"NodeID":          "NodeID",
		"ExpandedNodeID":  "ExpandedNodeID",
		"StatusCode":      "StatusCode",
		"QualifiedName":   "QualifiedName",
		"LocalizedText":   "LocalizedText",
		"ExtensionObject": "ExtensionObject",
		"DataValue":       "DataValue",
		"Variant":         "Variant",
		"DiagnosticInfo":  "DiagnosticInfo",
	}

	goCaseReplacer = strings.NewReplacer(
		"Identity", "Identity",
		"Guid", "GUID",
		"Id", "ID",
		"Json", "JSON",
		"QualityOfService", "QoS",
		"Tcp", "TCP",
		"Uadp", "UADP",
		"Uri", "URI",
		"Url", "URL",
		"Xml", "XML",
		"Https", "HTTPS",
		"Dns", "DNS",
		"_", "",
	)
)

func main() {
	log.SetFlags(0)

	flag.StringVar(&in, "in", ".", "Path to input directory")
	flag.StringVar(&out, "out", ".", "Path to output directory")
	flag.Parse()

	statusCodes, err := readStatusCodes(path.Join(in, "StatusCode.csv"))
	if err != nil {
		log.Fatalf("Failed to read status codes: %s", err)
	}
	writeStatusCodes(statusCodes, path.Join(out, "status_code.generated.go"))

	nodeIDs, err := readNodeIDs(path.Join(in, "NodeIds.csv"))
	if err != nil {
		log.Fatalf("Failed to read nodeID definitions: %s", err)
	}
	writeNodeIDs(nodeIDs, path.Join(out, "nodeids.generated.go"))

	dict, err := readTypes(path.Join(in, "Opc.Ua.Types.bsd"))
	if err != nil {
		log.Fatalf("Failed to read type definitions: %s", err)
	}
	enums := makeEnums(dict)
	structs := makeStructs(dict, enums)
	writeEnums(enums, path.Join(out, "enums.generated.go"))
	writeStructs(structs, path.Join(out, "structs.generated.go"))
}

type statusCode struct {
	Name        string
	Value       string
	Description string
}

func readStatusCodes(filename string) ([]statusCode, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		log.Fatalf("Error parsing %s: %v", filename, err)
	}
	statusCodes := make([]statusCode, len(rows))
	for i := range rows {
		statusCodes[i] = statusCode{Name: goCaseReplacer.Replace(rows[i][0]), Value: rows[i][1], Description: rows[i][2]}
	}
	return statusCodes, nil
}

func writeStatusCodes(statusCodes []statusCode, filename string) {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 4, 4, 4, ' ', 0)
	t1 := template.Must(template.New("").Parse(tmplStatus))
	if err := t1.Execute(w, statusCodes); err != nil {
		log.Fatalf("Failed to generate statusCodes: %s", err)
	}
	if err := ioutil.WriteFile(filename, b.Bytes(), 0644); err != nil {
		log.Fatalf("Failed to write '%s': %v", filename, err)
	}
}

type nodeID struct {
	Name  string
	Value string
}

func readNodeIDs(filename string) ([]nodeID, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		log.Fatalf("Error parsing %s: %v", filename, err)
	}
	nodeIDs := make([]nodeID, len(rows))
	for i := range rows {
		nodeIDs[i] = nodeID{Name: goCaseReplacer.Replace(rows[i][2] + "ID" + rows[i][0]), Value: rows[i][1]}
	}
	return nodeIDs, nil
}

func writeNodeIDs(nodeIDs []nodeID, filename string) {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 4, 4, 4, ' ', 0)
	t1 := template.Must(template.New("").Parse(tmplNodeIDs))
	if err := t1.Execute(w, nodeIDs); err != nil {
		log.Fatalf("Failed to generate nodeids: %s", err)
	}
	if err := ioutil.WriteFile(filename, b.Bytes(), 0644); err != nil {
		log.Fatalf("Failed to write '%s': %v", filename, err)
	}
}

func writeEnums(enums []*enumType, filename string) {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 4, 4, 4, ' ', 0)
	t1 := template.Must(template.New("").Parse(tmplEnum))
	if err := t1.Execute(w, enums); err != nil {
		log.Fatalf("Failed to generate enums: %s", err)
	}
	if err := ioutil.WriteFile(filename, b.Bytes(), 0644); err != nil {
		log.Fatalf("Failed to write '%s': %v", filename, err)
	}
}

func writeStructs(structs []*structType, filename string) {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 4, 4, 4, ' ', 0)
	t1 := template.Must(template.New("").Parse(tmplStruct))
	if err := t1.Execute(w, structs); err != nil {
		log.Fatalf("Failed to generate structs: %s", err)
	}
	if err := ioutil.WriteFile(filename, b.Bytes(), 0644); err != nil {
		log.Fatalf("Failed to write '%s': %v", filename, err)
	}
}

func makeField(sf *structuredField, enums []*enumType) *structField {
	t := strings.TrimPrefix(sf.Type, "ua:")
	t = strings.TrimPrefix(t, "tns:")
	t = strings.TrimPrefix(t, "opc:")
	t = goCaseReplacer.Replace(t)

	// Is built-in?
	if t2, found := builtInTypeMap[t]; found {
		if len(sf.LengthField) > 0 {
			return &structField{
				Name:    goCaseReplacer.Replace(sf.Name),
				Type:    t2,
				IsSlice: true,
			}
		} else {
			return &structField{
				Name: goCaseReplacer.Replace(sf.Name),
				Type: t2,
			}
		}
	}

	// Is embedded?
	if t == "RequestHeader" {
		return &structField{
			Name:       "RequestHeader",
			Type:       "RequestHeader",
			IsEmbedded: true,
		}
	}
	if t == "ResponseHeader" {
		return &structField{
			Name:       "ResponseHeader",
			Type:       "ResponseHeader",
			IsEmbedded: true,
		}
	}

	// Is enum?
	isEnum := false
	for _, e := range enums {
		if e.Name == t {
			isEnum = true
			break
		}
	}
	if isEnum {
		if len(sf.LengthField) > 0 {
			return &structField{
				Name:    goCaseReplacer.Replace(sf.Name),
				Type:    t,
				IsSlice: true,
				IsEnum:  true,
			}
		} else {
			return &structField{
				Name:   goCaseReplacer.Replace(sf.Name),
				Type:   t,
				IsEnum: true,
			}
		}
	}

	// structs
	if len(sf.LengthField) > 0 {
		return &structField{
			Name:    goCaseReplacer.Replace(sf.Name),
			Type:    t,
			IsSlice: true,
		}
	} else {
		return &structField{
			Name: goCaseReplacer.Replace(sf.Name),
			Type: t,
		}
	}

}

type enumType struct {
	Name   string
	Type   string
	Values []*enumValue
}

type enumValue struct {
	Name  string
	Value int
}

func makeEnums(dict *typeDictionary) []*enumType {
	enums := make([]*enumType, len(dict.EnumeratedTypes))
	for i, et := range dict.EnumeratedTypes {
		values := make([]*enumValue, len(et.Values))
		for j, ev := range et.Values {
			values[j] = &enumValue{Name: goCaseReplacer.Replace(ev.Name), Value: ev.Value}
		}
		enums[i] = &enumType{Name: goCaseReplacer.Replace(et.Name), Type: "int32", Values: values}
	}
	return enums
}

type structType struct {
	Name   string
	Type   string
	Fields []*structField
}

type structField struct {
	Name       string
	Type       string
	IsEmbedded bool
	IsSlice    bool
	IsEnum     bool
}

func makeStructs(dict *typeDictionary, enums []*enumType) []*structType {
	structs := make([]*structType, 0, len(dict.StructuredTypes))
	for _, st := range dict.StructuredTypes {
		if len(st.BaseType) > 0 {
			fields := make([]*structField, 0, len(st.Fields))
			for _, sf := range st.Fields {
				skip := false
				for _, ff := range st.Fields {
					if sf.Name == ff.LengthField {
						skip = true
						break
					}
				}
				if !skip {
					fields = append(fields, makeField(sf, enums))
				}
			}
			structs = append(structs, &structType{Name: goCaseReplacer.Replace(st.Name), Fields: fields})
		}
	}
	return structs
}

type typeDictionary struct {
	XMLName         xml.Name          `xml:"TypeDictionary"`
	StructuredTypes []*structuredType `xml:"StructuredType"`
	EnumeratedTypes []*enumeratedType `xml:"EnumeratedType"`
}

type enumeratedType struct {
	Name   string             `xml:",attr"`
	Bits   int                `xml:"LengthInBits,attr"`
	Doc    string             `xml:"Documentation"`
	Values []*enumeratedValue `xml:"EnumeratedValue"`
}

type enumeratedValue struct {
	Name  string `xml:",attr"`
	Value int    `xml:",attr"`
}

type structuredType struct {
	Name     string             `xml:",attr"`
	BaseType string             `xml:"BaseType,attr"`
	Doc      string             `xml:"Documentation"`
	Fields   []*structuredField `xml:"Field"`
}

type structuredField struct {
	Name        string `xml:",attr"`
	Type        string `xml:"TypeName,attr"`
	LengthField string `xml:",attr"`
	SwitchField string `xml:",attr"`
	SwitchValue string `xml:",attr"`
}

func readTypes(filename string) (*typeDictionary, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	d := new(typeDictionary)
	if err := xml.NewDecoder(f).Decode(&d); err != nil {
		return nil, err
	}

	return d, nil
}

var tmplStatus = `// Copyright 2021 Converter Systems LLC. All rights reserved.

// Code generated by go generate; DO NOT EDIT.

package ua

const (
	{{- range $j, $v := .}}
	// {{$v.Description}}
	{{$v.Name}}	StatusCode = {{$v.Value}}
	{{- end}}
)

// Error returns the StatusCode message.
func (c StatusCode) Error() string {
	switch c {
	case Good:
		return "The operation completed successfully."
	{{- range $j, $v := .}}
	case {{$v.Name}}:
		return "{{$v.Description}}"
	{{- end}}
	default:
		return "An unknown error occurred."
	}
}
`

var tmplEnum = `// Copyright 2021 Converter Systems LLC. All rights reserved.

// Code generated by go generate; DO NOT EDIT.

package ua
{{range $i, $e := .}}
// {{$e.Name}} enumeration.
type {{$e.Name}} int32

// {{$e.Name}} enumeration.
const (
	{{- range $j, $v := $e.Values}}
	{{$e.Name}}{{$v.Name}}	{{$e.Name}} = {{$v.Value}}
	{{- end}}
)

// String returns enumeration value as string.
func (v {{$e.Name}}) String() string {
	switch v { 
	{{- range $j, $v := $e.Values}}
	case {{$v.Value}}: 
		return "{{$v.Name}}"
	{{- end}}
	default:
		return ""
	}
}
{{end}}
`

var tmplStruct = `// Copyright 2021 Converter Systems LLC. All rights reserved.

// Code generated by go generate; DO NOT EDIT.

package ua

import (
	"reflect"
	"time"

	"github.com/google/uuid"
)
{{range $i, $s := .}}
// {{$s.Name}} structure.
type {{$s.Name}} struct {
	{{- range $j, $f := $s.Fields}}
	{{- if $f.IsEmbedded}}
	{{$f.Type}}
	{{- else}}
	{{- if $f.IsSlice}}
	{{$f.Name}}	[]{{$f.Type}}
	{{- else}}
	{{$f.Name}}	{{$f.Type}}
	{{- end}}
	{{- end}}
	{{- end}}
}

{{end}}

func init() {
	{{- range $i, $s := .}}
		RegisterBinaryEncodingID(reflect.TypeOf((*{{$s.Name}})(nil)).Elem(), NewExpandedNodeID(ObjectID{{$s.Name}}EncodingDefaultBinary))
	{{- end}}
}
`

var tmplNodeIDs = `// Copyright 2021 Converter Systems LLC. All rights reserved.

// Code generated by go generate; DO NOT EDIT.

package ua

// Well-known NodeIDs
var (
{{- range $i, $s := .}}
	{{$s.Name}}	NodeID = NewNodeIDNumeric(0, {{$s.Value}})
{{- end}}
)
`
