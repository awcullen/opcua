// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

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

// ParseBrowsePath returns a slice of QualifiedNames from a string, e.g. ParseBrowsePath("2:Demo/2:Dynamic")
func ParseBrowsePath(s string) []QualifiedName {
	//TODO: see part4 Annex A.2
	toks := strings.Split(s, "/")
	path := make([]QualifiedName, len(toks))
	for i, tok := range toks {
		path[i] = ParseQualifiedName(tok)
	}
	return path
}

// String returns a string representation, e.g. "2:Demo"
func (a QualifiedName) String() string {
	return fmt.Sprintf("%d:%s", a.NamespaceIndex, a.Name)
}

func (a QualifiedName) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}
