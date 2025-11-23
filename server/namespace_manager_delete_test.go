// Copyright 2021 Converter Systems LLC. All rights reserved.

package server

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/awcullen/opcua/ua"
)

// Helper function to create a minimal test server
func createTestServer(t *testing.T) *Server {
	host, _ := os.Hostname()
	port := 46020 // Use different port to avoid conflicts

	srv, err := New(
		ua.ApplicationDescription{
			ApplicationURI: fmt.Sprintf("urn:%s:testserver-delete", host),
			ProductURI:     "http://github.com/awcullen/opcua",
			ApplicationName: ua.LocalizedText{
				Text:   "DeleteNodeTest",
				Locale: "en",
			},
			ApplicationType:     ua.ApplicationTypeServer,
			GatewayServerURI:    "",
			DiscoveryProfileURI: "",
			DiscoveryURLs:       []string{fmt.Sprintf("opc.tcp://%s:%d", host, port)},
		},
		"./pki/server.crt",
		"./pki/server.key",
		fmt.Sprintf("opc.tcp://%s:%d", host, port),
		WithAuthenticateAnonymousIdentityFunc(func(userIdentity ua.AnonymousIdentity, applicationURI string, endpointURL string) error {
			return nil
		}),
		WithSecurityPolicyNone(true),
	)
	if err != nil {
		t.Fatalf("Error creating server: %v", err)
	}
	return srv
}

// TestDeleteNodeByID_BasicVariable tests deleting a simple variable node
func TestDeleteNodeByID_BasicVariable(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	// Create a test variable node
	nodeID := ua.NewNodeIDString(nsIdx, "TestVariable")
	testNode := NewVariableNode(
		srv,
		nodeID,
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

	// Add node
	err := nm.AddNode(testNode)
	if err != nil {
		t.Fatalf("Error adding node: %v", err)
	}

	// Verify node exists
	if _, ok := nm.FindNode(nodeID); !ok {
		t.Fatal("Node not found after adding")
	}

	// Delete node
	err = nm.DeleteNodeByID(nodeID)
	if err != nil {
		t.Fatalf("Error deleting node: %v", err)
	}

	// Verify node is gone
	if _, ok := nm.FindNode(nodeID); ok {
		t.Fatal("Node still exists after deletion")
	}
}

// TestDeleteNodeByID_NonExistent tests deleting a non-existent node
func TestDeleteNodeByID_NonExistent(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	// Try to delete non-existent node
	nodeID := ua.NewNodeIDString(nsIdx, "NonExistent")
	err := nm.DeleteNodeByID(nodeID)

	if err != ua.BadNodeIDUnknown {
		t.Fatalf("Expected BadNodeIDUnknown, got: %v", err)
	}
}

// TestDeleteNodeByID_ProtectedStandardNamespace tests protection of ns=0 nodes
func TestDeleteNodeByID_ProtectedStandardNamespace(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()

	// Try to delete a node in namespace 0
	err := nm.DeleteNodeByID(ua.ObjectIDServer)
	if err != ua.BadNodeIDInvalid {
		t.Fatalf("Expected BadNodeIDInvalid for ns=0 node, got: %v", err)
	}
}

// TestDeleteNodeByID_ProtectedObjectsFolder tests protection of ObjectsFolder
func TestDeleteNodeByID_ProtectedObjectsFolder(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()

	// Try to delete ObjectsFolder
	err := nm.DeleteNodeByID(ua.ObjectIDObjectsFolder)
	if err != ua.BadNodeIDInvalid {
		t.Fatalf("Expected BadNodeIDInvalid for ObjectsFolder, got: %v", err)
	}
}

// TestDeleteNodeByIDRecursive_SimpleHierarchy tests recursive deletion with parent and children
func TestDeleteNodeByIDRecursive_SimpleHierarchy(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	// Create parent node
	parentID := ua.NewNodeIDString(nsIdx, "Parent")
	parentNode := NewObjectNode(
		srv,
		parentID,
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

	// Create child nodes
	child1ID := ua.NewNodeIDString(nsIdx, "Child1")
	child1Node := NewVariableNode(
		srv,
		child1ID,
		ua.NewQualifiedName(nsIdx, "Child1"),
		ua.NewLocalizedText("Child1", "en"),
		ua.NewLocalizedText("Child variable 1", "en"),
		nil,
		[]ua.Reference{
			{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, IsInverse: false, TargetID: ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)},
			{ReferenceTypeID: ua.ReferenceTypeIDHasComponent, IsInverse: true, TargetID: ua.NewExpandedNodeID(parentID)},
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

	child2ID := ua.NewNodeIDString(nsIdx, "Child2")
	child2Node := NewVariableNode(
		srv,
		child2ID,
		ua.NewQualifiedName(nsIdx, "Child2"),
		ua.NewLocalizedText("Child2", "en"),
		ua.NewLocalizedText("Child variable 2", "en"),
		nil,
		[]ua.Reference{
			{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, IsInverse: false, TargetID: ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)},
			{ReferenceTypeID: ua.ReferenceTypeIDHasComponent, IsInverse: true, TargetID: ua.NewExpandedNodeID(parentID)},
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

	// Add nodes
	err := nm.AddNodes(parentNode, child1Node, child2Node)
	if err != nil {
		t.Fatalf("Error adding nodes: %v", err)
	}

	// Verify all nodes exist
	if _, ok := nm.FindNode(parentID); !ok {
		t.Fatal("Parent node not found after adding")
	}
	if _, ok := nm.FindNode(child1ID); !ok {
		t.Fatal("Child1 node not found after adding")
	}
	if _, ok := nm.FindNode(child2ID); !ok {
		t.Fatal("Child2 node not found after adding")
	}

	// Delete recursively
	count, err := nm.DeleteNodeByIDRecursive(parentID)
	if err != nil {
		t.Fatalf("Error deleting recursively: %v", err)
	}

	// Verify count (parent + 2 children = 3)
	if count != 3 {
		t.Fatalf("Expected count of 3, got: %d", count)
	}

	// Verify all nodes are gone
	if _, ok := nm.FindNode(parentID); ok {
		t.Fatal("Parent node still exists after recursive deletion")
	}
	if _, ok := nm.FindNode(child1ID); ok {
		t.Fatal("Child1 node still exists after recursive deletion")
	}
	if _, ok := nm.FindNode(child2ID); ok {
		t.Fatal("Child2 node still exists after recursive deletion")
	}
}

// TestDeleteNodeByIDRecursive_NonExistent tests recursive deletion of non-existent node
func TestDeleteNodeByIDRecursive_NonExistent(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	// Try to delete non-existent node recursively
	nodeID := ua.NewNodeIDString(nsIdx, "NonExistent")
	count, err := nm.DeleteNodeByIDRecursive(nodeID)

	if err != ua.BadNodeIDUnknown {
		t.Fatalf("Expected BadNodeIDUnknown, got: %v", err)
	}
	if count != 0 {
		t.Fatalf("Expected count of 0, got: %d", count)
	}
}

// TestDeleteNodeByIDRecursive_ProtectedNode tests recursive deletion protection
func TestDeleteNodeByIDRecursive_ProtectedNode(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()

	// Try to recursively delete ObjectsFolder
	count, err := nm.DeleteNodeByIDRecursive(ua.ObjectIDObjectsFolder)
	if err != ua.BadNodeIDInvalid {
		t.Fatalf("Expected BadNodeIDInvalid for ObjectsFolder, got: %v", err)
	}
	if count != 0 {
		t.Fatalf("Expected count of 0, got: %d", count)
	}
}

// TestConcurrentDelete tests concurrent deletion operations
func TestConcurrentDelete(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	// Create multiple test nodes
	const nodeCount = 10
	nodeIDs := make([]ua.NodeID, nodeCount)

	for i := 0; i < nodeCount; i++ {
		nodeID := ua.NewNodeIDString(nsIdx, "ConcurrentTest"+string(rune('0'+i)))
		nodeIDs[i] = nodeID

		testNode := NewVariableNode(
			srv,
			nodeID,
			ua.NewQualifiedName(nsIdx, "ConcurrentTest"+string(rune('0'+i))),
			ua.NewLocalizedText("Test", "en"),
			ua.NewLocalizedText("Test", "en"),
			nil,
			[]ua.Reference{
				{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, IsInverse: false, TargetID: ua.NewExpandedNodeID(ua.VariableTypeIDBaseDataVariableType)},
				{ReferenceTypeID: ua.ReferenceTypeIDOrganizes, IsInverse: true, TargetID: ua.NewExpandedNodeID(ua.ObjectIDObjectsFolder)},
			},
			ua.DataValue{Value: int32(i)},
			ua.DataTypeIDInt32,
			ua.ValueRankScalar,
			nil,
			ua.AccessLevelsCurrentRead,
			300.0,
			false,
			nil,
		)

		err := nm.AddNode(testNode)
		if err != nil {
			t.Fatalf("Error adding node %d: %v", i, err)
		}
	}

	// Delete concurrently
	var wg sync.WaitGroup
	errors := make([]error, nodeCount)

	for i := 0; i < nodeCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errors[idx] = nm.DeleteNodeByID(nodeIDs[idx])
		}(i)
	}

	wg.Wait()

	// Verify all deletions succeeded
	for i, err := range errors {
		if err != nil {
			t.Errorf("Error deleting node %d: %v", i, err)
		}
	}

	// Verify all nodes are gone
	for i, nodeID := range nodeIDs {
		if _, ok := nm.FindNode(nodeID); ok {
			t.Errorf("Node %d still exists after concurrent deletion", i)
		}
	}
}

// TestDeleteWithReadAccess tests deletion while another goroutine reads
func TestDeleteWithReadAccess(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	nodeID := ua.NewNodeIDString(nsIdx, "ReadTest")
	testNode := NewVariableNode(
		srv,
		nodeID,
		ua.NewQualifiedName(nsIdx, "ReadTest"),
		ua.NewLocalizedText("ReadTest", "en"),
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

	err := nm.AddNode(testNode)
	if err != nil {
		t.Fatalf("Error adding node: %v", err)
	}

	// Start reader goroutine
	done := make(chan bool)
	go func() {
		for i := 0; i < 100; i++ {
			nm.FindNode(nodeID)
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()

	// Delete after a short delay
	time.Sleep(10 * time.Millisecond)
	err = nm.DeleteNodeByID(nodeID)
	if err != nil {
		t.Fatalf("Error deleting node: %v", err)
	}

	// Wait for reader to finish
	<-done

	// Verify node is gone
	if _, ok := nm.FindNode(nodeID); ok {
		t.Fatal("Node still exists after deletion")
	}
}

// TestReferenceIntegrity tests that bidirectional references are cleaned up
func TestReferenceIntegrity(t *testing.T) {
	srv := createTestServer(t)
	defer srv.Close()

	nm := srv.NamespaceManager()
	nsIdx := nm.Add("http://test.org/test")

	// Create node that references ObjectsFolder
	nodeID := ua.NewNodeIDString(nsIdx, "RefTest")
	testNode := NewVariableNode(
		srv,
		nodeID,
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

	err := nm.AddNode(testNode)
	if err != nil {
		t.Fatalf("Error adding node: %v", err)
	}

	// Get ObjectsFolder and check it has reference to our node
	objFolder, ok := nm.FindObject(ua.ObjectIDObjectsFolder)
	if !ok {
		t.Fatal("ObjectsFolder not found")
	}

	// Count references to our node before deletion
	refCountBefore := 0
	for _, ref := range objFolder.References() {
		if ua.ToNodeID(ref.TargetID, nm.NamespaceUris()) == nodeID {
			refCountBefore++
		}
	}

	if refCountBefore == 0 {
		t.Fatal("ObjectsFolder doesn't have reference to test node")
	}

	// Delete our node
	err = nm.DeleteNodeByID(nodeID)
	if err != nil {
		t.Fatalf("Error deleting node: %v", err)
	}

	// Check that ObjectsFolder no longer has reference to our node
	objFolder, ok = nm.FindObject(ua.ObjectIDObjectsFolder)
	if !ok {
		t.Fatal("ObjectsFolder not found after deletion")
	}

	refCountAfter := 0
	for _, ref := range objFolder.References() {
		if ua.ToNodeID(ref.TargetID, nm.NamespaceUris()) == nodeID {
			refCountAfter++
		}
	}

	if refCountAfter != 0 {
		t.Fatalf("ObjectsFolder still has %d references to deleted node", refCountAfter)
	}
}
