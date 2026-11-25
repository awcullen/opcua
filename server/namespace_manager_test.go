// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"testing"

	"github.com/awcullen/opcua/ua"
)

// Helper function to create a minimal test server
func createTestServer(t *testing.T) *Server {
	srv, err := New(
		ua.ApplicationDescription{
			ApplicationURI: "urn:testhost:testserver",
			ProductURI:     "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{
				Text:   "testserver@testhost",
				Locale: "en",
			},
			ApplicationType:     ua.ApplicationTypeServer,
			GatewayServerURI:    "",
			DiscoveryProfileURI: "",
			DiscoveryURLs:       []string{"opc.tcp://testhost:4840"},
		},
		"./pki/server.crt",
		"./pki/server.key",
		"opc.tcp://testhost:4840",
	)
	if err != nil {
		t.Fatalf("Error creating server: %v", err)
	}
	return srv
}

// TestDeleteNodes_BasicVariable tests deleting a simple variable node
func TestDeleteNodes_BasicVariable(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	// create node
	node := NewVariableNode(
		srv,
		ua.NewNodeIDString(nsIdx, "TestVariable"),
		ua.NewQualifiedName(nsIdx, "TestVariable"),
		ua.NewLocalizedText("TestVariable", "en"),
		ua.NewLocalizedText("Test variable for deletion", "en"),
		nil,
		[]ua.Reference{
			{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, IsInverse: false, TargetID: ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)},
			{ReferenceTypeID: ua.ReferenceTypeIDOrganizes, IsInverse: true, TargetID: ua.NewExpandedNodeID(ua.ObjectIDObjectsFolder)},
		},
		ua.DataValue{Value: int32(42)},
		ua.DataTypeIDInt32,
		ua.ValueRankScalar,
		nil,
		ua.AccessLevelsCurrentRead|ua.AccessLevelsCurrentWrite,
		300.0,
		false,
		nil,
	)

	// add node
	if err := nm.AddNodes(node); err != nil {
		t.Fatalf("Error adding node: %v", err)
	}

	// verify node exists
	if _, ok := nm.FindNode(node.NodeID()); !ok {
		t.Fatal("Node not found after adding")
	}

	// delete node
	if err := nm.DeleteNodes(node.NodeID()); err != nil {
		t.Fatalf("Error deleting node: %v", err)
	}

	// verify node is gone
	if _, ok := nm.FindNode(node.NodeID()); ok {
		t.Fatal("Node found after deletion")
	}
}

// TestDeleteNodes_NonExistent tests deleting a non-existent node
func TestDeleteNodes_NonExistent(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	// create id
	nodeID := ua.NewNodeIDString(nsIdx, "TestVariable")

	// deleting nodeID that has not been added should not cause error
	if err := nm.DeleteNodes(nodeID); err != nil {
		t.Fatalf("Error deleting node: %v", err)
	}
}

// TestDeleteNodes_ProtectedStandardNamespace tests protection of ns=0 nodes
func TestDeleteNodes_ProtectedStandardNamespace(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()

	// try to delete a protected node
	nm.DeleteNodes(ua.ObjectIDServer)

	// verify protected node still exists
	if _, ok := nm.FindNode(ua.ObjectIDServer); !ok {
		t.Fatal("Node not found")
	}
}

// TestDeleteNodes_SimpleHierarchy tests deletion of parent and children
func TestDeleteNodes_SimpleHierarchy(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	// create parent node
	parent := NewObjectNode(
		srv,
		ua.NewNodeIDString(nsIdx, "Parent"),
		ua.NewQualifiedName(nsIdx, "Parent"),
		ua.NewLocalizedText("Parent", "en"),
		ua.NewLocalizedText("Parent object", "en"),
		nil,
		[]ua.Reference{
			{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, IsInverse: false, TargetID: ua.NewExpandedNodeID(ua.ObjectTypeIDFolderType)},
			{ReferenceTypeID: ua.ReferenceTypeIDOrganizes, IsInverse: true, TargetID: ua.NewExpandedNodeID(ua.ObjectIDObjectsFolder)},
		},
		ua.EventNotifierNone,
	)

	// create child nodes
	child1 := NewVariableNode(
		srv,
		ua.NewNodeIDString(nsIdx, "Child1"),
		ua.NewQualifiedName(nsIdx, "Child1"),
		ua.NewLocalizedText("Child1", "en"),
		ua.NewLocalizedText("Child variable 1", "en"),
		nil,
		[]ua.Reference{
			{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, IsInverse: false, TargetID: ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)},
			{ReferenceTypeID: ua.ReferenceTypeIDHasComponent, IsInverse: true, TargetID: ua.NewExpandedNodeID(parent.NodeID())},
		},
		ua.DataValue{Value: int32(1)},
		ua.DataTypeIDInt32,
		ua.ValueRankScalar,
		nil,
		ua.AccessLevelsCurrentRead,
		300.0,
		false,
		nil,
	)

	child2 := NewVariableNode(
		srv,
		ua.NewNodeIDString(nsIdx, "Child2"),
		ua.NewQualifiedName(nsIdx, "Child2"),
		ua.NewLocalizedText("Child2", "en"),
		ua.NewLocalizedText("Child variable 2", "en"),
		nil,
		[]ua.Reference{
			{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, IsInverse: false, TargetID: ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)},
			{ReferenceTypeID: ua.ReferenceTypeIDHasComponent, IsInverse: true, TargetID: ua.NewExpandedNodeID(parent.NodeID())},
		},
		ua.DataValue{Value: int32(2)},
		ua.DataTypeIDInt32,
		ua.ValueRankScalar,
		nil,
		ua.AccessLevelsCurrentRead,
		300.0,
		false,
		nil,
	)

	// add nodes
	if err := nm.AddNodes(parent, child1, child2); err != nil {
		t.Fatalf("Error adding nodes: %v", err)
	}

	// verify all nodes exist
	if _, ok := nm.FindNode(parent.NodeID()); !ok {
		t.Fatal("Parent node not found after adding")
	}
	if _, ok := nm.FindNode(child1.NodeID()); !ok {
		t.Fatal("Child1 node not found after adding")
	}
	if _, ok := nm.FindNode(child2.NodeID()); !ok {
		t.Fatal("Child2 node not found after adding")
	}

	// delete parent and children
	if err := nm.DeleteNodes(parent.NodeID()); err != nil {
		t.Fatalf("Error deleting nodes: %v", err)
	}

	// verify all nodes are gone
	if _, ok := nm.FindNode(parent.NodeID()); ok {
		t.Fatal("Parent node still exists after recursive deletion")
	}
	if _, ok := nm.FindNode(child1.NodeID()); ok {
		t.Fatal("Child1 node still exists after recursive deletion")
	}
	if _, ok := nm.FindNode(child2.NodeID()); ok {
		t.Fatal("Child2 node still exists after recursive deletion")
	}
}

// TestReferenceIntegrity tests that bidirectional references are cleaned up
func TestReferenceIntegrity(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	// create node that references ObjectsFolder
	node := NewVariableNode(
		srv,
		ua.NewNodeIDString(nsIdx, "RefTest"),
		ua.NewQualifiedName(nsIdx, "RefTest"),
		ua.NewLocalizedText("RefTest", "en"),
		ua.NewLocalizedText("Test", "en"),
		nil,
		[]ua.Reference{
			{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, IsInverse: false, TargetID: ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)},
			{ReferenceTypeID: ua.ReferenceTypeIDOrganizes, IsInverse: true, TargetID: ua.NewExpandedNodeID(ua.ObjectIDObjectsFolder)},
		},
		ua.DataValue{Value: int32(42)},
		ua.DataTypeIDInt32,
		ua.ValueRankScalar,
		nil,
		ua.AccessLevelsCurrentRead,
		300.0,
		false,
		nil,
	)

	// add node
	err := nm.AddNodes(node)
	if err != nil {
		t.Fatalf("Error adding node: %v", err)
	}

	// find ObjectsFolder node
	objFolder, ok := nm.FindObject(ua.ObjectIDObjectsFolder)
	if !ok {
		t.Fatal("ObjectsFolder not found")
	}

	// count references to node before deletion
	refCount := 0
	for _, ref := range objFolder.References() {
		if ua.ToNodeID(ref.TargetID, nm.NamespaceUris()) == node.NodeID() {
			refCount++
		}
	}

	// verify refCount == 1
	if refCount != 1 {
		t.Fatal("ObjectsFolder doesn't have reference to test node")
	}

	// delete node
	if err = nm.DeleteNodes(node.NodeID()); err != nil {
		t.Fatalf("Error deleting node: %v", err)
	}

	refCount = 0
	for _, ref := range objFolder.References() {
		if ua.ToNodeID(ref.TargetID, nm.NamespaceUris()) == node.NodeID() {
			refCount++
		}
	}

	// verify refCount == 0
	if refCount != 0 {
		t.Fatalf("ObjectsFolder still has %d references to deleted node", refCount)
	}
}
