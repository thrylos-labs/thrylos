package core

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/thrylos-labs/thrylos/shared"
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
	// Create a temporary directory for blockchain data
	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir) // Ensure cleanup of the temporary directory

	shard := NewShard(1, 10) // Initialize shard with appropriate arguments
	knownPeers := []string{} // Empty slice for known peers

	// Update with correct arguments including dataDir
	node := NewNode("localhost:8080", knownPeers, tempDir, shard, true)

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
	shard := NewShard(1, 10) // Initialize shard with appropriate arguments
	knownPeers := []string{} // Empty slice for known peers

	// Create a temporary directory for blockchain data
	tempDir1, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory for node1: %v", err)
	}
	defer os.RemoveAll(tempDir1) // Ensure cleanup of the temporary directory for node1

	tempDir2, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory for node2: %v", err)
	}
	defer os.RemoveAll(tempDir2) // Ensure cleanup of the temporary directory for node2

	// Initialize nodes with their respective temporary directories
	node1 := NewNode("localhost:8080", knownPeers, tempDir1, shard, true)
	node2 := NewNode("localhost:8081", knownPeers, tempDir2, shard, true)

	shard.AssignNode(node1)
	shard.AssignNode(node2)
	shard.RedistributeData()

	// Add tests to check if the data (like UTXOs) is correctly redistributed
	// This will depend on your implementation of RedistributeData
}

func TestShardUnderHighLoad(t *testing.T) {
	shard := NewShard(1, 100) // Set the shard capacity to 100

	for i := 0; i < 100; i++ {
		// Create a temporary directory for each node's blockchain data
		tempDir, err := ioutil.TempDir("", fmt.Sprintf("blockchain_test_%d", i))
		if err != nil {
			t.Fatalf("Failed to create temporary directory for node %d: %v", i, err)
		}
		defer os.RemoveAll(tempDir) // Ensure cleanup of the temporary directory

		nodeAddress := fmt.Sprintf("localhost:%d", 8080+i)
		node := NewNode(nodeAddress, []string{}, tempDir, shard, true)
		if err := shard.AssignNode(node); err != nil {
			t.Errorf("Failed to assign node %d to shard: %v", i, err)
		}
	}

	if len(shard.Nodes) != 100 {
		t.Errorf("Expected 100 nodes in shard, got %d", len(shard.Nodes))
	}
}

func TestShardNodeFailureRecovery(t *testing.T) {
	// Ensure that the shard is created with a capacity of 100
	shard := NewShard(1, 100)

	// Create a temporary directory for blockchain data
	tempDir, err := ioutil.TempDir("", "blockchain_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir) // Ensure cleanup of the temporary directory

	// Initialize node with the temporary directory
	node := NewNode("localhost:8080", []string{}, tempDir, shard, true)
	shard.AssignNode(node)

	// Simulate node failure
	// This could involve marking the node as inactive, removing it from the shard, etc.
	// ...

	// Test shard's recovery mechanism
	// This could involve redistributing data, reassigning transactions, etc.
	// ...
}

func TestCrossShardTransactions(t *testing.T) {
	shard1 := NewShard(1, 10)
	shard2 := NewShard(2, 10)

	// Temporary directories for each node
	tempDir1, err := ioutil.TempDir("", "blockchain_test_shard1_node1")
	if err != nil {
		t.Fatalf("Failed to create temporary directory for shard1 node1: %v", err)
	}
	defer os.RemoveAll(tempDir1)

	tempDir2, err := ioutil.TempDir("", "blockchain_test_shard2_node1")
	if err != nil {
		t.Fatalf("Failed to create temporary directory for shard2 node1: %v", err)
	}
	defer os.RemoveAll(tempDir2)

	node1 := NewNode("localhost:8080", []string{}, tempDir1, shard1, true)
	node2 := NewNode("localhost:8081", []string{}, tempDir2, shard2, true)

	shard1.AssignNode(node1)
	shard2.AssignNode(node2)

	// Simulate a transaction that spans across both shards
	// ...
}

func TestShardDataConsistency(t *testing.T) {
	shard := NewShard(1, 10)

	// Temporary directories for each node
	tempDir1, err := ioutil.TempDir("", "blockchain_test_shard1_node")
	if err != nil {
		t.Fatalf("Failed to create temporary directory for shard node1: %v", err)
	}
	defer os.RemoveAll(tempDir1)

	tempDir2, err := ioutil.TempDir("", "blockchain_test_shard1_node2")
	if err != nil {
		t.Fatalf("Failed to create temporary directory for shard node2: %v", err)
	}
	defer os.RemoveAll(tempDir2)

	node1 := NewNode("localhost:8080", []string{}, tempDir1, shard, true)
	node2 := NewNode("localhost:8081", []string{}, tempDir2, shard, true)

	shard.AssignNode(node1)
	shard.AssignNode(node2)

	// Simulate activities that change the state
	// Ensure that the state changes are consistent and synchronized across all nodes in the shard
	// ...
}

func NewTestNode(address string, shard *Shard) *Node {
	// Use a static directory and empty slice for peers for testing
	tempDir := "/tmp" // This would be a mock or a suitable temporary directory.
	knownPeers := []string{}
	return NewNode(address, knownPeers, tempDir, shard, true) // true indicates it is a test environment
}

// Doesn't test well now

func TestDistributeUTXOs(t *testing.T) {
	shard := NewShard(1, 3)

	// Temporary directory paths and known peers setup for example purposes
	tempDir1, tempDir2, tempDir3 := "/tmp/node1", "/tmp/node2", "/tmp/node3"
	knownPeers := []string{} // assuming no known peers for simplicity

	node1 := NewNode("node1", knownPeers, tempDir1, shard, true) // Set isTest to true
	node2 := NewNode("node2", knownPeers, tempDir2, shard, true) // Set isTest to true
	node3 := NewNode("node3", knownPeers, tempDir3, shard, true) // Set isTest to true

	shard.AddNode(node1)
	shard.AddNode(node2)
	shard.AddNode(node3)

	ring := NewConsistentHashRing()
	nodes := []*Node{node1, node2, node3}
	for _, node := range nodes {
		ring.AddNode(node.Address)
	}

	// Populate shared.AllUTXOs with some test data
	shared.AllUTXOs = []shared.UTXO{
		{TransactionID: "tx1", Index: 0, OwnerAddress: "addr1", Amount: 100},
		{TransactionID: "tx2", Index: 0, OwnerAddress: "addr2", Amount: 200},
		{TransactionID: "tx3", Index: 0, OwnerAddress: "addr3", Amount: 300},
	}

	allUTXOs := shared.GetAllUTXOs()

	// Debug: Print all UTXOs fetched
	fmt.Printf("All UTXOs: %+v\n", allUTXOs)

	distributedUTXOs := shard.distributeUTXOs(allUTXOs)

	// Debug: Print the distribution map
	for key, _ := range allUTXOs {
		nodeAddr := ring.GetNode(key)
		fmt.Printf("Key %s is mapped to Node %s\n", key, nodeAddr)
	}

	for nodeAddr, utxos := range distributedUTXOs {
		fmt.Printf("Node %s received %d UTXOs\n", nodeAddr, len(utxos))
		if len(utxos) == 0 {
			t.Errorf("%s received no UTXOs, expected at least one", nodeAddr)
		}
	}
}

// NewTestNode creates a new Node with simplified parameters for testing purposes.

func TestReplicateUTXO(t *testing.T) {
	shard := NewShard(1, 3)
	node1 := NewTestNode("node1", shard)
	node2 := NewTestNode("node2", shard)
	node3 := NewTestNode("node3", shard)

	shard.AddNode(node1)
	shard.AddNode(node2)
	shard.AddNode(node3)

	// Initialize the consistent hash ring in shard
	ring := NewConsistentHashRing()
	ring.AddNode(node1.Address)
	ring.AddNode(node2.Address)
	ring.AddNode(node3.Address)

	// Mock a UTXO and its transaction ID
	txID := "tx1"
	utxo := shared.UTXO{TransactionID: txID, OwnerAddress: "addr1", Amount: 100}

	// Replicate the UTXO
	replicateUTXO(txID, utxo, node1.Address, ring, shard.Nodes)

	// Check if UTXO is replicated correctly
	if len(node1.ResponsibleUTXOs) == 0 || len(node2.ResponsibleUTXOs) == 0 || len(node3.ResponsibleUTXOs) == 0 {
		t.Errorf("UTXO replication failed, one of the nodes does not have the UTXO")
	}
	// Additional checks for exact replication details
}

// Additional tests can be written to cover more complex scenarios,
// such as testing inter-node communication within a shard,
// shard balancing (redistributing nodes and data among shards),
// and handling node failures or network issues.
