package processor

import (
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
)

// The DAG (Directed Acyclic Graph) processor organises transactions into a structure where each new transaction approves a few previous ones.
// Transactions validate each other instead of waiting for blocks, which makes the system faster as transactions are processed in parallel instead of waiting for a single queue.

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
	processChan chan *txProcessRequest
	workers     int
	msgCh       chan shared.Message // Channel for receiving messages

}

type TransactionVertex struct {
	Transaction  *thrylos.Transaction
	References   []string
	ReferencedBy []string
	Score        float64
	IsConfirmed  bool
	Timestamp    time.Time
}

type txProcessRequest struct {
	tx       *thrylos.Transaction
	respChan chan error
}

func NewDAGManager() *DAGManager {
	dm := &DAGManager{
		vertices:    make(map[string]*TransactionVertex),
		tips:        make(map[string]*TransactionVertex),
		processChan: make(chan *txProcessRequest, 1000),
		msgCh:       make(chan shared.Message, 100),
	}

	// Subscribe to relevant message types
	messageBus := shared.GetMessageBus()
	messageBus.Subscribe(shared.ValidateDAGTx, dm.msgCh)
	messageBus.Subscribe(shared.UpdateDAGState, dm.msgCh)
	messageBus.Subscribe(shared.GetDAGTips, dm.msgCh)

	// Start message handler
	go dm.handleMessages()

	// Start minimal number of workers
	for i := 0; i < runtime.NumCPU(); i++ {
		go dm.processWorker()
	}

	return dm
}

func (dm *DAGManager) handleMessages() {
	for msg := range dm.msgCh {
		switch msg.Type {
		case shared.ValidateDAGTx:
			dm.handleValidateTransaction(msg)
		case shared.UpdateDAGState:
			dm.handleUpdateState(msg)
		case shared.GetDAGTips:
			dm.handleGetTips(msg)
		}
	}
}

func (dm *DAGManager) handleGetTips(msg shared.Message) {
	dm.RLock()
	tips := make([]string, 0, len(dm.tips))
	for tipID := range dm.tips {
		tips = append(tips, tipID)
	}
	dm.RUnlock()

	msg.ResponseCh <- shared.Response{Data: tips}
}

func (dm *DAGManager) handleValidateTransaction(msg shared.Message) {
	tx := msg.Data.(*thrylos.Transaction)
	err := dm.AddTransaction(tx)
	msg.ResponseCh <- shared.Response{Error: err}
}

func (dm *DAGManager) processWorker() {
	for req := range dm.processChan {
		req.respChan <- dm.processTransaction(req.tx)
	}
}

func (dm *DAGManager) handleUpdateState(msg shared.Message) {
	req := msg.Data.(shared.UpdateTransactionStateRequest) // Match the type we're sending
	dm.Lock()
	if vertex, exists := dm.vertices[req.TransactionID]; exists {
		vertex.IsConfirmed = true
		// Only notify if state actually changed
		if req.State == "confirmed" && !vertex.IsConfirmed {
			dm.notifyStateChange(vertex)
		}
	}
	dm.Unlock()
	msg.ResponseCh <- shared.Response{}
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

	tips := dm.selectTips()
	for _, tip := range tips {
		vertex.References = append(vertex.References, tip.Transaction.GetId())
		tip.ReferencedBy = append(tip.ReferencedBy, txID)

		if len(tip.ReferencedBy) >= ConfirmationThreshold {
			tip.IsConfirmed = true
			// Only use message system when communicating with node
			dm.notifyNodeOfConfirmation(tip.Transaction)
		}

		delete(dm.tips, tip.Transaction.GetId())
	}

	dm.vertices[txID] = vertex
	dm.tips[txID] = vertex

	return nil
}

func (dm *DAGManager) notifyTransactionConfirmed(tx *thrylos.Transaction) {
	responseCh := make(chan shared.Response)
	shared.GetMessageBus().Publish(shared.Message{
		Type:       shared.ProcessBlock,
		Data:       tx,
		ResponseCh: responseCh,
	})
	// We don't wait for response as this is asynchronous notification
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
	// Internal method - no message system needed
	tips := make([]*TransactionVertex, 0, MinReferences)
	if len(dm.tips) < MinReferences {
		for _, tip := range dm.tips {
			tips = append(tips, tip)
		}
		return tips
	}

	var candidates []*TransactionVertex
	for _, tip := range dm.tips {
		if time.Since(tip.Timestamp) < 500*time.Millisecond {
			candidates = append(candidates, tip)
		}
	}

	for i := 0; i < MinReferences && len(candidates) > 0; i++ {
		idx := rand.Intn(len(candidates))
		tips = append(tips, candidates[idx])
		candidates = append(candidates[:idx], candidates[idx+1:]...)
	}

	return tips
}

func (dm *DAGManager) notifyStateChange(vertex *TransactionVertex) {
	responseCh := make(chan shared.Response)
	shared.GetMessageBus().Publish(shared.Message{
		Type: shared.UpdateState,
		Data: shared.UpdateTransactionStateRequest{
			TransactionID: vertex.Transaction.GetId(),
			State:         "confirmed",
		},
		ResponseCh: responseCh,
	})
}

func (dm *DAGManager) notifyNodeOfConfirmation(tx *thrylos.Transaction) {
	responseCh := make(chan shared.Response)
	shared.GetMessageBus().Publish(shared.Message{
		Type:       shared.ProcessBlock,
		Data:       tx,
		ResponseCh: responseCh,
	})
	// Async notification to node
}

func (dm *DAGManager) GetConfirmationStatus(txID string) (bool, error) {
	dm.RLock()
	defer dm.RUnlock()

	if vertex, exists := dm.vertices[txID]; exists {
		return vertex.IsConfirmed, nil
	}
	return false, fmt.Errorf("transaction not found")
}
