package core

import "crypto/sha256"

// MerkleNode represents a single node within a Merkle tree. Each node can have a left and right child,
// and holds data which, in the context of a blockchain, is usually a hash derived from transactions or
// other hashes. Leaf nodes contain hashes of transaction data, while non-leaf nodes contain hashes derived
// from their children's data.
type MerkleNode struct {
	Left  *MerkleNode // Pointer to the left child node.
	Right *MerkleNode // Pointer to the right child node.
	Data  []byte      // Data holds the hash. For leaf nodes, it's derived from transaction data; for non-leaf nodes, it's derived from the hashes of its child nodes.
}

// MerkleTree represents a binary tree where each leaf node is the hash of transaction data, and each non-leaf
// node is the hash of the concatenation of its children's hashes. The root of the tree (RootNode) provides a
// single hash that summarizes all of the transaction data in the tree, enabling efficient data verification.
type MerkleTree struct {
	RootNode *MerkleNode
}

// NewMerkleNode creates a new MerkleNode given a set of left and right child nodes and node data. If both
// left and right are nil, the node is assumed to be a leaf node, and its data is hashed. Otherwise, the node
// is an internal node, and its data is the hash of the concatenation of its children's data.
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := MerkleNode{}

	if left == nil && right == nil {
		hash := sha256.Sum256(data)
		node.Data = hash[:]
	} else {
		prevHashes := append(left.Data, right.Data...)
		hash := sha256.Sum256(prevHashes)
		node.Data = hash[:]
	}

	node.Left = left
	node.Right = right

	return &node
}

// NewMerkleTree constructs a MerkleTree from an array of data ([]byte). Each piece of data becomes a leaf node
// in the tree. The tree is constructed bottom-up, with leaf nodes hashed first, then internal nodes created
// from pairs of child nodes until a single root is formed. If an odd number of nodes exist at any level,
// the last node is duplicated to ensure pairing.
func NewMerkleTree(data [][]byte) *MerkleTree {
	var nodes []MerkleNode

	// Initialize leaf nodes with data.
	for _, datum := range data {
		node := NewMerkleNode(nil, nil, datum)
		nodes = append(nodes, *node)
	}

	if len(nodes) == 0 {
		return nil // Return nil if there's no data to form a tree.
	}

	// Iteratively combine nodes until the root is formed.
	for len(nodes) > 1 {
		levelNodes := []MerkleNode{}
		for j := 0; j < len(nodes); j += 2 {
			if j+1 < len(nodes) {
				node := NewMerkleNode(&nodes[j], &nodes[j+1], nil)
				levelNodes = append(levelNodes, *node)
			} else {
				node := NewMerkleNode(&nodes[j], &nodes[j], nil) // Pairing last node with itself
				levelNodes = append(levelNodes, *node)
			}
		}
		nodes = levelNodes // Move up one level in the tree.
	}

	tree := MerkleTree{&nodes[0]} // The last remaining node is the root.
	return &tree
}
