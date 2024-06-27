package core

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"time"

	"github.com/stathat/consistent"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
)

var rng *rand.Rand

func init() {
	// Initialize a new random source
	source := rand.NewSource(time.Now().UnixNano())
	rng = rand.New(source) // Create a new Rand instance with the source
}

const replicationFactor = 3 // Define how many nodes each UTXO should be replicated to

type ConsistentHashRing struct {
	*consistent.Consistent
}

func NewConsistentHashRing() *ConsistentHashRing {
	c := consistent.New()
	return &ConsistentHashRing{c}
}

func (c *ConsistentHashRing) AddNode(node string) {
	c.Consistent.Add(node)
}

func (c *ConsistentHashRing) GetNode(key string) string {
	node, err := c.Consistent.Get(key)
	if err != nil {
		// Handle the error, perhaps returning an empty string or a default node
		return ""
	}
	return node
}

func (c *ConsistentHashRing) GetReplicas(key string, count int) []string {
	nodes, err := c.Consistent.GetN(key, count)
	if err != nil {
		// Handle the error, perhaps returning nil or an empty slice
		return []string{}
	}
	return nodes
}

func (c *ConsistentHashRing) ProxyGetHash(value string) uint32 {
	h := fnv.New32a() // Or any other hash function used by your consistent hash library
	h.Write([]byte(value))
	return h.Sum32()
}

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

// Initialize or update the shard, including UTXO redistribution
// Initialize or update the shard, including UTXO redistribution
func (s *Shard) InitializeOrUpdateShard() {
	allUTXOs := shared.GetAllUTXOs() // Now returns a map
	s.UTXOs = allUTXOs               // Ensure s.UTXOs is also a map of the same type

	// Redistribute data among nodes
	s.RedistributeData()

	// Distribute UTXOs using the new shard configuration
	distributedUTXOs := s.distributeUTXOs(allUTXOs)
	s.applyDistributedUTXOs(distributedUTXOs)
}

// Applies the UTXO distribution to the nodes within the shard
func (s *Shard) applyDistributedUTXOs(distribution map[string][]*thrylos.UTXO) {
	// Clear existing UTXOs to avoid duplication
	for _, node := range s.Nodes {
		node.ResponsibleUTXOs = make(map[string]shared.UTXO)
	}

	// Apply the distributed UTXOs
	for nodeAddr, utxos := range distribution {
		for _, node := range s.Nodes {
			if node.Address == nodeAddr {
				for _, utxo := range utxos {
					txID := utxo.TransactionId // directly using the string
					node.ResponsibleUTXOs[txID] = shared.UTXO{
						TransactionID: txID,
						Index:         int(utxo.Index),
						OwnerAddress:  utxo.OwnerAddress,
						Amount:        int64(utxo.Amount),
					}
				}
				break
			}
		}
	}

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

// RedistributeData redistributes UTXOs among nodes based on a consistent hashing mechanism
func (s *Shard) RedistributeData() {
	ring := NewConsistentHashRing()
	for _, node := range s.Nodes {
		ring.AddNode(node.Address)
	}

	// Example for how UTXOs might be redistributed based on transaction IDs
	for txID, utxo := range s.UTXOs {
		responsibleNodeAddr := ring.GetNode(txID)
		for _, node := range s.Nodes {
			if node.Address == responsibleNodeAddr {
				node.ResponsibleUTXOs[txID] = utxo
				break
			}
		}
	}
}

func replicateUTXO(txID string, utxo shared.UTXO, primaryAddr string, ring *ConsistentHashRing, nodes []*Node) {
	responsibleNodeAddr := ring.GetNode(txID)
	for _, node := range nodes {
		if node.Address == responsibleNodeAddr {
			node.AssignUTXO(txID, utxo) // Pass the transaction ID as a string and the UTXO
			break
		}
	}

	// Replicate UTXO responsibility
	replicas := ring.GetReplicas(txID, replicationFactor)
	for _, replicaAddr := range replicas {
		if replicaAddr == responsibleNodeAddr {
			continue // Skip primary responsible node
		}
		for _, node := range nodes {
			if node.Address == replicaAddr {
				node.AssignUTXO(txID, utxo) // Pass the transaction ID and the UTXO
				break
			}
		}
	}
}

func (n *Node) AssignUTXO(txID string, utxo shared.UTXO) {
	// Assign UTXO to the node's local storage using a map
	n.ResponsibleUTXOs[txID] = utxo
}

// distributeUTXOs serves as a placeholder for the logic required to distribute UTXOs among the nodes in the shard.
// This method should be implemented to ensure a balanced distribution of transaction outputs for processing and storage.
func (s *Shard) distributeUTXOs(allUTXOs map[string]shared.UTXO) map[string][]*thrylos.UTXO {
	distributedUTXOs := make(map[string][]*thrylos.UTXO)
	ring := NewConsistentHashRing()

	for _, node := range s.Nodes {
		ring.AddNode(node.Address)
		distributedUTXOs[node.Address] = []*thrylos.UTXO{} // Ensure initialization
	}

	for key, utxo := range allUTXOs {
		replicas := ring.GetReplicas(key, replicationFactor) // Ensure UTXOs are replicated
		for _, nodeAddr := range replicas {
			protoUTXO := shared.ConvertSharedUTXOToProto(utxo)
			distributedUTXOs[nodeAddr] = append(distributedUTXOs[nodeAddr], protoUTXO)
		}
	}

	for nodeAddr, utxos := range distributedUTXOs {
		fmt.Printf("Node %s received %d UTXOs\n", nodeAddr, len(utxos))
	}

	return distributedUTXOs
}

// Shard Initialization and Node Management: Shards are subsets of the network designed to scale by distributing the workload. Nodes are added to shards, and their capacity is managed to prevent overloading.
// Data Redistribution: Implements logic for distributing data (like UTXOs) among nodes in a shard to balance load and ensure efficient data management.
