package core

import (
	"fmt"
	"testing"
)

// TestNewShard tests the creation of a new shard.
func TestNewShard(t *testing.T) {
	shardID := 1
	maxNodes := 10 // Example limit for testing
	shard := NewShard(shardID, maxNodes)

	if shard == nil {
		t.Fatal("Failed to create a new shard")
	}

	if shard.ID != shardID {
		t.Errorf("Expected shard ID to be %d, got %d", shardID, shard.ID)
	}

	if len(shard.Nodes) != 0 {
		t.Errorf("Expected shard to have 0 nodes, got %d", len(shard.Nodes))
	}

	if len(shard.UTXOs) != 0 {
		t.Errorf("Expected shard to have 0 UTXOs, got %d", len(shard.UTXOs))
	}

	if len(shard.Blocks) != 0 {
		t.Errorf("Expected shard to have 0 blocks, got %d", len(shard.Blocks))
	}
}

// TestAddNodeToShard tests adding a node to a shard.

func TestAssignNodeToShard(t *testing.T) {
	shard := NewShard(1, 10) // Update with maxNodes argument
	knownPeers := []string{} // Empty slice for known peers
	node := NewNode("localhost:8080", knownPeers, shard, true)

	if err := shard.AssignNode(node); err != nil {
		t.Errorf("Failed to assign node to shard: %v", err)
	}

	// Check the number of nodes after the assignment
	if len(shard.Nodes) != 1 {
		t.Errorf("Expected 1 node in shard, got %d", len(shard.Nodes))
	}

	// Attempt to add the same node again
	if err := shard.AssignNode(node); err != nil {
		t.Errorf("Error assigning the same node again: %v", err)
	}

	// The count should still be 1
	if len(shard.Nodes) != 1 {
		t.Errorf("Expected 1 node in shard after re-adding the same node, got %d", len(shard.Nodes))
	}
}

func TestRedistributeData(t *testing.T) {
	shard := NewShard(1, 10) // Update with maxNodes argument
	knownPeers := []string{} // Empty slice for known peers
	node1 := NewNode("localhost:8080", knownPeers, shard, true)
	node2 := NewNode("localhost:8081", knownPeers, shard, true)

	shard.AssignNode(node1)
	shard.AssignNode(node2)
	shard.RedistributeData()

	// Add tests to check if the data (like UTXOs) is correctly redistributed
	// This will depend on your implementation of RedistributeData
}

func TestShardUnderHighLoad(t *testing.T) {
	shard := NewShard(1, 100) // Set the shard capacity to 100

	for i := 0; i < 100; i++ {
		node := NewNode(fmt.Sprintf("localhost:%d", 8080+i), []string{}, shard, true)
		if err := shard.AssignNode(node); err != nil {
			t.Errorf("Failed to assign node %d to shard: %v", i, err)
		}
	}

	if len(shard.Nodes) != 100 {
		t.Errorf("Expected 100 nodes in shard, got %d", len(shard.Nodes))
	}
}

func TestShardNodeFailureRecovery(t *testing.T) {
	shard := NewShard(1, 100) // Ensure that the shard is created with a capacity of 100
	node := NewNode("localhost:8080", []string{}, shard, true)
	shard.AssignNode(node)

	// Simulate node failure
	// This could involve marking the node as inactive, removing it from the shard, etc.
	// ...

	// Test shard's recovery mechanism
	// This could involve redistributing data, reassigning transactions, etc.
	// ...
}

func TestCrossShardTransactions(t *testing.T) {
	shard1 := NewShard(1, 10) // Update with maxNodes argument
	shard2 := NewShard(2, 10) // Update with maxNodes argument

	node1 := NewNode("localhost:8080", []string{}, shard1, true)
	node2 := NewNode("localhost:8081", []string{}, shard2, true)

	shard1.AssignNode(node1)
	shard2.AssignNode(node2)

	// Simulate a transaction that spans across both shards
	// This would involve creating a transaction that impacts data in both shard1 and shard2
	// ...
}

func TestShardDataConsistency(t *testing.T) {
	shard := NewShard(1, 10) // Update with maxNodes argument
	node1 := NewNode("localhost:8080", []string{}, shard, true)
	node2 := NewNode("localhost:8081", []string{}, shard, true)

	shard.AssignNode(node1)
	shard.AssignNode(node2)

	// Simulate activities that change the state (like transactions)
	// Ensure that the state changes are consistent and synchronized across all nodes in the shard
	// ...
}

// Additional tests can be written to cover more complex scenarios,
// such as testing inter-node communication within a shard,
// shard balancing (redistributing nodes and data among shards),
// and handling node failures or network issues.
