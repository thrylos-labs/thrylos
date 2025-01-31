package processor

import (
	"fmt"
	"math/rand"
	"runtime"
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

type DAGManager struct {
	vertices map[string]*TransactionVertex
	tips     map[string]*TransactionVertex
	sync.RWMutex
	node        *Node
	processChan chan *txProcessRequest
	workers     int
}

type txProcessRequest struct {
	tx       *thrylos.Transaction
	respChan chan error
}

func NewDAGManager(node *Node) *DAGManager {
	dm := &DAGManager{
		vertices:    make(map[string]*TransactionVertex),
		tips:        make(map[string]*TransactionVertex),
		node:        node,
		processChan: make(chan *txProcessRequest, 1000),
	}

	// Start minimal number of workers
	for i := 0; i < runtime.NumCPU(); i++ {
		go dm.processWorker()
	}

	return dm
}

func (dm *DAGManager) processWorker() {
	for req := range dm.processChan {
		req.respChan <- dm.processTransaction(req.tx)
	}
}

func (dm *DAGManager) processTransaction(tx *thrylos.Transaction) error {
	dm.Lock()
	defer dm.Unlock()

	txID := tx.GetId()
	if _, exists := dm.vertices[txID]; exists {
		return fmt.Errorf("transaction already exists in DAG")
	}

	vertex := &TransactionVertex{
		Transaction:  tx,
		References:   make([]string, 0, MinReferences),
		ReferencedBy: make([]string, 0),
		Timestamp:    time.Now(),
		Score:        1.0,
	}

	// Fast tip selection with pre-allocated slice
	tips := make([]*TransactionVertex, 0, MinReferences)
	for _, tip := range dm.tips {
		if time.Since(tip.Timestamp) < 100*time.Millisecond {
			tips = append(tips, tip)
			if len(tips) == MinReferences {
				break
			}
		}
	}

	// Add references
	for _, tip := range tips {
		vertex.References = append(vertex.References, tip.Transaction.GetId())
		tip.ReferencedBy = append(tip.ReferencedBy, txID)

		// Check if this reference confirms the tip
		if len(tip.ReferencedBy) >= ConfirmationThreshold {
			tip.IsConfirmed = true
			statusIface, _ := dm.node.txStatusMap.LoadOrStore(tip.Transaction.GetId(), &TransactionStatus{})
			tipStatus := statusIface.(*TransactionStatus)

			tipStatus.Lock()
			if !tipStatus.ConfirmedByDAG {
				tipStatus.ConfirmedByDAG = true
				if tipStatus.ProcessedByModern {
					go dm.node.handleProcessedTransaction(tip.Transaction)
				}
			}
			tipStatus.Unlock()
		}

		delete(dm.tips, tip.Transaction.GetId())
	}

	dm.vertices[txID] = vertex
	dm.tips[txID] = vertex

	return nil
}

func (dm *DAGManager) AddTransaction(tx *thrylos.Transaction) error {
	respChan := make(chan error, 1)
	dm.processChan <- &txProcessRequest{
		tx:       tx,
		respChan: respChan,
	}

	return <-respChan
}

func (dm *DAGManager) selectTips() []*TransactionVertex {
	tips := make([]*TransactionVertex, 0, MinReferences)
	if len(dm.tips) < MinReferences {
		for _, tip := range dm.tips {
			tips = append(tips, tip)
		}
		return tips
	}

	// Get recent tips
	var candidates []*TransactionVertex
	for _, tip := range dm.tips {
		if time.Since(tip.Timestamp) < 500*time.Millisecond {
			candidates = append(candidates, tip)
		}
	}

	// Select random tips from candidates
	for i := 0; i < MinReferences && len(candidates) > 0; i++ {
		idx := rand.Intn(len(candidates))
		tips = append(tips, candidates[idx])
		candidates = append(candidates[:idx], candidates[idx+1:]...)
	}

	return tips
}

func (dm *DAGManager) GetConfirmationStatus(txID string) (bool, error) {
	dm.RLock()
	defer dm.RUnlock()

	if vertex, exists := dm.vertices[txID]; exists {
		return vertex.IsConfirmed, nil
	}
	return false, fmt.Errorf("transaction not found")
}

type TransactionVertex struct {
	Transaction  *thrylos.Transaction
	References   []string
	ReferencedBy []string
	Score        float64
	IsConfirmed  bool
	Timestamp    time.Time
}
