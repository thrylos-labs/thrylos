package core

import (
	"sync"

	thrylos "github.com/thrylos-labs/thrylos"
)

type Network struct {
	Nodes               []*Node
	PendingTransactions []*thrylos.Transaction
	mu                  sync.RWMutex
}

func NewNetwork() *Network {
	return &Network{
		Nodes:               make([]*Node, 0),
		PendingTransactions: make([]*thrylos.Transaction, 0),
	}
}

func (n *Network) AddNode(node *Node) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.Nodes = append(n.Nodes, node)
}

func (n *Network) RemoveNode(nodeAddress string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, node := range n.Nodes {
		if node.Address == nodeAddress {
			n.Nodes = append(n.Nodes[:i], n.Nodes[i+1:]...)
			break
		}
	}
}

func (n *Network) AddPendingTransaction(tx *thrylos.Transaction) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.PendingTransactions = append(n.PendingTransactions, tx)
}

func (n *Network) RemovePendingTransaction(txID string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, tx := range n.PendingTransactions {
		if tx.Id == txID {
			n.PendingTransactions = append(n.PendingTransactions[:i], n.PendingTransactions[i+1:]...)
			break
		}
	}
}

func (n *Network) GetTotalNodeCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.Nodes)
}

func (n *Network) GetTotalPendingTransactions() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.PendingTransactions)
}

func (n *Network) GetAllNodes() []*Node {
	n.mu.RLock()
	defer n.mu.RUnlock()
	nodesCopy := make([]*Node, len(n.Nodes))
	copy(nodesCopy, n.Nodes)
	return nodesCopy
}
