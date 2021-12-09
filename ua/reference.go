package ua

// Reference ...
type Reference struct {
	ReferenceTypeID NodeID
	IsInverse       bool
	TargetID        ExpandedNodeID
}

func NewReference(referenceTypeID NodeID, isInverse bool, targetID ExpandedNodeID) Reference {
	return Reference{referenceTypeID, isInverse, targetID}
}
