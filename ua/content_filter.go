// Copyright 2021 Converter Systems LLC. All rights reserved.

package ua

func EqualSimpleAttributeOperand(a, b SimpleAttributeOperand) bool {
	if a.TypeDefinitionID != ObjectTypeIDBaseEventType && a.TypeDefinitionID != b.TypeDefinitionID {
		return false
	}
	if len(a.BrowsePath) != len(b.BrowsePath) {
		return false
	}
	for i := 0; i < len(a.BrowsePath); i++ {
		if a.BrowsePath[i] != b.BrowsePath[i] {
			return false
		}
	}
	if a.AttributeID != b.AttributeID {
		return false
	}
	if a.IndexRange != b.IndexRange {
		return false
	}
	return true
}
