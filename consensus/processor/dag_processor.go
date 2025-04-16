package processor

import (
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/types"
	"golang.org/x/exp/rand"
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
	msgCh       chan types.Message // Channel for receiving messages

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
		msgCh:       make(chan types.Message, 100),
		// workers field is assigned below if needed, or just used in loop
	}

	// Subscribe to relevant message types using the singleton getter
	// --- CHANGE HERE ---
	messageBus := types.GetGlobalMessageBus() // Use the canonical singleton getter from 'types'
	// --- END CHANGE ---
	log.Printf("DEBUG: [NewDAGManager] Subscribing to MessageBus instance at %p", messageBus) // Keep log
	messageBus.Subscribe(types.ValidateDAGTx, dm.msgCh)
	messageBus.Subscribe(types.UpdateDAGState, dm.msgCh)
	messageBus.Subscribe(types.GetDAGTips, dm.msgCh)

	// Start message handler
	log.Println("INFO: [DAGManager] Starting internal message handler goroutine...")
	go dm.handleMessages()

	// Start minimal number of workers
	dm.workers = runtime.NumCPU() // Assign worker count if needed elsewhere
	log.Printf("INFO: [DAGManager] Starting %d process worker goroutines...", dm.workers)
	for i := 0; i < dm.workers; i++ {
		go dm.processWorker() // Pass worker ID for logging
	}

	return dm
}

func (dm *DAGManager) handleMessages() {
	log.Println("INFO: [DAGManager.handleMessages] Goroutine entered loop, waiting for messages...") // You see this
	// --- ADD THIS ---
	log.Println("DEBUG: [DAGManager.handleMessages] Entering FOR range loop...")
	// --- END ADD ---
	for msg := range dm.msgCh {
		// --- ADD THIS ---
		log.Printf("DEBUG: [DAGManager.handleMessages] READ message from channel! Type: %s", msg.Type)
		// --- END ADD ---

		// Log receipt BEFORE the switch (Already suggested, but confirm it's there)
		log.Printf("DEBUG: [DAGManager.handleMessages] Received message Type: %s - Processing switch...", msg.Type)
		switch msg.Type {
		case types.ValidateDAGTx:
			log.Printf("DEBUG: [DAGManager.handleMessages] Routing to handleValidateTransaction for Type: %s", msg.Type)
			dm.handleValidateTransaction(msg)
		case types.UpdateDAGState:
			log.Printf("DEBUG: [DAGManager.handleMessages] Routing to handleUpdateState for Type: %s", msg.Type)
			dm.handleUpdateState(msg)
		case types.GetDAGTips:
			log.Printf("DEBUG: [DAGManager.handleMessages] Routing to handleGetTips for Type: %s", msg.Type)
			dm.handleGetTips(msg)
		default:
			log.Printf("WARN: [DAGManager.handleMessages] Received unhandled message type: %s", msg.Type)
			if msg.ResponseCh != nil {
				msg.ResponseCh <- types.Response{Error: fmt.Errorf("DAGManager received unhandled message type: %s", msg.Type)}
			}
		}
		// --- ADD THIS ---
		log.Printf("DEBUG: [DAGManager.handleMessages] Finished processing switch for Type: %s. Looping...", msg.Type)
		// --- END ADD ---
	}
	log.Println("WARN: [DAGManager.handleMessages] msgCh channel closed, handler loop exiting.")
}

func (dm *DAGManager) handleGetTips(msg types.Message) {
	dm.RLock()
	tips := make([]string, 0, len(dm.tips))
	for tipID := range dm.tips {
		tips = append(tips, tipID)
	}
	dm.RUnlock()

	msg.ResponseCh <- types.Response{Data: tips}
}

func (dm *DAGManager) handleValidateTransaction(msg types.Message) {
	tx := msg.Data.(*thrylos.Transaction)
	err := dm.AddTransaction(tx)
	msg.ResponseCh <- types.Response{Error: err}
}

func (dm *DAGManager) processWorker() {
	for req := range dm.processChan {
		req.respChan <- dm.processTransaction(req.tx)
	}
}

func (dm *DAGManager) handleUpdateState(msg types.Message) {
	req := msg.Data.(types.UpdateTransactionStateRequest) // Match the type we're sending
	dm.Lock()
	if vertex, exists := dm.vertices[req.TransactionID]; exists {
		vertex.IsConfirmed = true
		// Only notify if state actually changed
		if req.State == "confirmed" && !vertex.IsConfirmed {
			dm.notifyStateChange(vertex)
		}
	}
	dm.Unlock()
	msg.ResponseCh <- types.Response{}
}

func (dm *DAGManager) processTransaction(tx *thrylos.Transaction) error {
	// Add logging inside this critical function
	txID := tx.GetId()
	log.Printf("DEBUG: [DAGManager.processTransaction] Acquiring lock for TxID: %s", txID)
	dm.Lock()
	log.Printf("DEBUG: [DAGManager.processTransaction] Lock acquired for TxID: %s", txID)
	defer func() {
		log.Printf("DEBUG: [DAGManager.processTransaction] Releasing lock for TxID: %s", txID)
		dm.Unlock()
	}()

	log.Printf("DEBUG: [DAGManager.processTransaction] Checking existence for TxID: %s", txID)
	if _, exists := dm.vertices[txID]; exists {
		log.Printf("WARN: [DAGManager.processTransaction] Transaction %s already exists in DAG", txID)
		// Return the specific error so the handler can potentially ignore it
		return fmt.Errorf("transaction already exists in DAG")
	}

	vertex := &TransactionVertex{
		Transaction:  tx,
		References:   make([]string, 0, MinReferences),
		ReferencedBy: make([]string, 0),
		Timestamp:    time.Now(),
		Score:        1.0,
		IsConfirmed:  false, // Explicitly false initially
	}

	log.Printf("DEBUG: [DAGManager.processTransaction] Selecting tips for TxID: %s", txID)
	tips := dm.selectTips()
	log.Printf("DEBUG: [DAGManager.processTransaction] Selected %d tips for TxID: %s", len(tips), txID)

	// Check if enough tips were selected
	if len(tips) < MinReferences && len(dm.vertices) > 0 { // Allow < MinReferences only if DAG is empty
		log.Printf("WARN: [DAGManager.processTransaction] Not enough tips (%d < %d) found for TxID: %s", len(tips), MinReferences, txID)
		// Decide how to handle this - return error or proceed with fewer refs?
		// Returning error for now, prevents adding dangling transactions.
		return fmt.Errorf("not enough tips (%d) found to reference", len(tips))
	}

	for _, tip := range tips {
		tipID := tip.Transaction.GetId()
		log.Printf("DEBUG: [DAGManager.processTransaction] Referencing tip %s for new TxID: %s", tipID, txID)
		vertex.References = append(vertex.References, tipID)
		tip.ReferencedBy = append(tip.ReferencedBy, txID)
		log.Printf("DEBUG: [DAGManager.processTransaction] Tip %s now referenced by %d transactions.", tipID, len(tip.ReferencedBy))

		if !tip.IsConfirmed && len(tip.ReferencedBy) >= ConfirmationThreshold {
			log.Printf("INFO: [DAGManager.processTransaction] Confirming Tip %s due to reference count (%d >= %d)", tipID, len(tip.ReferencedBy), ConfirmationThreshold)
			tip.IsConfirmed = true
			dm.notifyNodeOfConfirmation(tip.Transaction) // Notify asynchronously
		}

		log.Printf("DEBUG: [DAGManager.processTransaction] Removing tip %s from tip set.", tipID)
		delete(dm.tips, tipID)
	}

	log.Printf("DEBUG: [DAGManager.processTransaction] Adding new vertex %s to vertices map.", txID)
	dm.vertices[txID] = vertex
	log.Printf("DEBUG: [DAGManager.processTransaction] Adding new vertex %s to tip set.", txID)
	dm.tips[txID] = vertex
	// Prune tips if pool is too large - implement pruning logic if needed

	log.Printf("DEBUG: [DAGManager.processTransaction] Finished processing TxID: %s successfully.", txID)
	return nil // Return nil for success
}

func (dm *DAGManager) notifyTransactionConfirmed(tx *thrylos.Transaction) {
	responseCh := make(chan types.Response)
	shared.GetMessageBus().Publish(types.Message{
		Type:       types.ProcessBlock,
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
	responseCh := make(chan types.Response)
	shared.GetMessageBus().Publish(types.Message{
		Type: types.UpdateState,
		Data: types.UpdateTransactionStateRequest{
			TransactionID: vertex.Transaction.GetId(),
			State:         "confirmed",
		},
		ResponseCh: responseCh,
	})
}

func (dm *DAGManager) notifyNodeOfConfirmation(tx *thrylos.Transaction) {
	responseCh := make(chan types.Response)
	shared.GetMessageBus().Publish(types.Message{
		Type:       types.ProcessBlock,
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
