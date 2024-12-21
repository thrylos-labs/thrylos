package core

import (
	"fmt"
	"sort"
	"sync"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
)

const (
	MaxReferences         = 3    // Maximum number of previous transactions a new transaction can reference
	MinReferences         = 2    // Minimum number of references required
	TipPoolSize           = 1000 // Maximum size of the tip pool
	ConfirmationThreshold = 5    // Number of subsequent references needed for confirmation
	AlphaMCMC             = 0.5  // Alpha parameter for MCMC tip selection
)

// DAGManager manages the Directed Acyclic Graph structure
// DAGManager - simplified version
type DAGManager struct {
	vertices map[string]*TransactionVertex
	tips     map[string]*TransactionVertex
	mutex    sync.RWMutex
	node     *Node
}

// NewDAGManager creates a new DAG manager
func NewDAGManager(node *Node) *DAGManager {
	return &DAGManager{
		vertices: make(map[string]*TransactionVertex),
		tips:     make(map[string]*TransactionVertex),
		node:     node,
	}
}

// AddTransaction adds a new transaction to the DAG
func (dm *DAGManager) AddTransaction(tx *thrylos.Transaction) error {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	// Check if transaction already exists
	if _, exists := dm.vertices[tx.GetId()]; exists {
		return fmt.Errorf("transaction already exists in DAG")
	}

	// Create new vertex
	vertex := &TransactionVertex{
		Transaction:  tx,
		References:   make([]string, 0),
		ReferencedBy: make([]string, 0),
		Timestamp:    time.Now(),
		Score:        1.0, // Initial score
	}

	// Get all tips
	tips := make([]*TransactionVertex, 0, len(dm.tips))
	for _, tip := range dm.tips {
		tips = append(tips, tip)
	}

	// Select references if we have enough tips
	if len(tips) > 0 {
		numRefs := MinReferences
		if len(tips) < MinReferences {
			numRefs = len(tips)
		}
		if numRefs > MaxReferences {
			numRefs = MaxReferences
		}

		// Sort tips by score
		sort.Slice(tips, func(i, j int) bool {
			return tips[i].Score > tips[j].Score
		})

		// Add references
		for i := 0; i < numRefs; i++ {
			refTx := tips[i]
			vertex.References = append(vertex.References, refTx.Transaction.GetId())
			refTx.ReferencedBy = append(refTx.ReferencedBy, tx.GetId())
			delete(dm.tips, refTx.Transaction.GetId())
		}
	}

	// Add to vertices map
	dm.vertices[tx.GetId()] = vertex
	dm.tips[tx.GetId()] = vertex

	// Update confirmations
	dm.updateConfirmations(vertex)

	return nil
}

// updateConfirmations updates confirmation status
func (dm *DAGManager) updateConfirmations(vertex *TransactionVertex) {
	// Mark as confirmed if it has enough references
	if len(vertex.ReferencedBy) >= ConfirmationThreshold {
		vertex.IsConfirmed = true
		// Notify node of confirmation
		dm.node.handleProcessedTransaction(vertex.Transaction)
	}

	// Check references
	for _, refID := range vertex.References {
		if ref, exists := dm.vertices[refID]; exists {
			if len(ref.ReferencedBy) >= ConfirmationThreshold && !ref.IsConfirmed {
				ref.IsConfirmed = true
				dm.node.handleProcessedTransaction(ref.Transaction)
			}
		}
	}
}

// GetConfirmationStatus returns the confirmation status of a transaction
func (dm *DAGManager) GetConfirmationStatus(txID string) (bool, error) {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	if vertex, exists := dm.vertices[txID]; exists {
		return vertex.IsConfirmed, nil
	}
	return false, fmt.Errorf("transaction not found")
}

// TransactionVertex represents a transaction in the DAG
type TransactionVertex struct {
	Transaction  *thrylos.Transaction
	References   []string
	ReferencedBy []string
	Score        float64
	IsConfirmed  bool
	Timestamp    time.Time
}
