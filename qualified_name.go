// Copyright 2020 Converter Systems LLC. All rights reserved.

package opcua

import (
	"fmt"
	"strconv"
	"strings"
)

// QualifiedName pairs a name and a namespace index.
type QualifiedName struct {
	NamespaceIndex uint16
	Name           string
}

// NewQualifiedName constructs a QualifiedName from a namespace index and a name.
func NewQualifiedName(ns uint16, text string) QualifiedName {
	return QualifiedName{ns, text}
}

// NilQualifiedName is the nil value.
var NilQualifiedName = QualifiedName{}

// ParseQualifiedName returns a QualifiedName from a string, e.g. ParseQualifiedName("2:Demo")
func ParseQualifiedName(s string) QualifiedName {
	var ns uint64
	var pos = strings.Index(s, ":")
	if pos == -1 {
		return QualifiedName{uint16(ns), s}
	}
	ns, err := strconv.ParseUint(s[:pos], 10, 16)
	if err != nil {
		return QualifiedName{uint16(ns), s}
	}
	s = s[pos+1:]
	return QualifiedName{uint16(ns), s}
}

// String returns a string representation, e.g. "2:Demo"
func (a QualifiedName) String() string {
	return fmt.Sprintf("%d:%s", a.NamespaceIndex, a.Name)
}
