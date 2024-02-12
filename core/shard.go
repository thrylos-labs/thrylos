package core

import (
	"Thrylos/shared"
	"fmt"
)

// Shard represents a subset of the blockchain network, designed to scale the network by dividing
// the transaction and block processing workload among multiple shards. Each shard maintains its own
// sequence of blocks, set of transactions (UTXOs), and participating nodes.
type Shard struct {
	ID       int                    // Unique identifier for the shard.
	Nodes    []*Node                // List of nodes that are part of the shard.
	UTXOs    map[string]shared.UTXO // Current state of unspent transaction outputs managed by this shard.
	Blocks   []*Block               // Blocks that have been confirmed and added to the shard's blockchain.
	MaxNodes int                    // Maximum number of nodes allowed to be part of the shard.
}

// NewShard initializes a new Shard with a specified identifier and maximum node capacity. It sets up
// the initial empty structures for nodes, UTXOs, and blocks within the shard.
func NewShard(id int, maxNodes int) *Shard {
	return &Shard{
		ID:       id,
		Nodes:    make([]*Node, 0),
		UTXOs:    make(map[string]shared.UTXO),
		Blocks:   make([]*Block, 0),
		MaxNodes: maxNodes,
	}
}

// AddNode adds a new node to the shard's list of participating nodes. This method registers a node
// as part of the shard, allowing it to participate in the shard's transaction and block processing activities.
// The method may include additional logic to integrate the node into the shard's operations.
func (s *Shard) AddNode(node *Node) {
	s.Nodes = append(s.Nodes, node)
	// Additional logic to integrate the node into the shard can be added here.
}

// AssignNode attempts to add a node to the shard, ensuring the node is not already a member and that
// the shard has not reached its maximum capacity. It returns an error if the shard is full or if the
// node is already part of the shard.
func (s *Shard) AssignNode(node *Node) error {
	// Check if node is already in the shard
	for _, n := range s.Nodes {
		if n == node {
			return nil // Node already exists in the shard, no action needed.
		}
	}

	// Check if the shard is at full capacity
	if len(s.Nodes) >= s.MaxNodes {
		return fmt.Errorf("shard %d is at maximum capacity", s.ID)
	}

	// Add the node to the shard
	s.Nodes = append(s.Nodes, node)
	return nil
}

// RedistributeData handles the logic for redistributing data, such as UTXOs, among nodes within the shard.
// This function is crucial for maintaining an even and efficient distribution of workload and data storage
// across the shard's nodes.
func (s *Shard) RedistributeData() {
	// Placeholder for logic to redistribute data among nodes in the shard.
	// Actual implementation should replace this placeholder with specific logic to ensure even distribution of UTXOs, for example.
	for _, node := range s.Nodes {
		// Example: Distribute UTXOs evenly among nodes.
		node.Blockchain.UTXOs = s.distributeUTXOs()
	}
}

// distributeUTXOs serves as a placeholder for the logic required to distribute UTXOs among the nodes in the shard.
// This method should be implemented to ensure a balanced distribution of transaction outputs for processing and storage.
func (s *Shard) distributeUTXOs() map[string][]shared.UTXO {
	// Placeholder function for UTXO distribution logic.
	// Implement specific logic for even distribution of UTXOs among shard nodes here.
	return make(map[string][]shared.UTXO)
}
