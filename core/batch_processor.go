package core

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
)

const (
	BatchSize          = 100 // Number of transactions per batch
	BatchTimeout       = 2   // Maximum time to wait for batch completion in seconds
	MaxConcurrentBatch = 5   // Maximum number of batches to process concurrently
	MinBatchSize       = 10  // Minimum number of transactions to trigger batch processing
)

type BatchProcessor struct {
	node              *Node
	batchQueue        chan *thrylos.Transaction
	processingBatches sync.WaitGroup
	batchMutex        sync.Mutex
	currentBatch      []*thrylos.Transaction
	isProcessing      bool
	processedTxs      sync.Map // Track processed transaction IDs

}

func NewBatchProcessor(node *Node) *BatchProcessor {
	bp := &BatchProcessor{
		node:         node,
		batchQueue:   make(chan *thrylos.Transaction, BatchSize*MaxConcurrentBatch),
		currentBatch: make([]*thrylos.Transaction, 0, BatchSize),
	}

	go bp.batchManager()
	return bp
}

func (bp *BatchProcessor) AddTransaction(tx *thrylos.Transaction) error {
	select {
	case bp.batchQueue <- tx:
		return nil
	default:
		return fmt.Errorf("batch queue is full")
	}
}

func (bp *BatchProcessor) batchManager() {
	ticker := time.NewTicker(time.Duration(BatchTimeout) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case tx := <-bp.batchQueue:
			bp.batchMutex.Lock()
			bp.currentBatch = append(bp.currentBatch, tx)

			if len(bp.currentBatch) >= BatchSize {
				bp.processBatch()
			}
			bp.batchMutex.Unlock()

		case <-ticker.C:
			bp.batchMutex.Lock()
			if len(bp.currentBatch) >= MinBatchSize {
				bp.processBatch()
			}
			bp.batchMutex.Unlock()
		}
	}
}

func (bp *BatchProcessor) processBatch() {
	if len(bp.currentBatch) == 0 {
		return
	}

	batch := make([]*thrylos.Transaction, len(bp.currentBatch))
	copy(batch, bp.currentBatch)
	bp.currentBatch = make([]*thrylos.Transaction, 0, BatchSize)

	bp.processingBatches.Add(1)
	go func(transactions []*thrylos.Transaction) {
		defer bp.processingBatches.Done()

		for _, tx := range transactions {
			// Check if transaction was already processed
			if _, exists := bp.processedTxs.Load(tx.GetId()); exists {
				continue
			}

			// Process through DAG first
			if err := bp.node.DAGManager.AddTransaction(tx); err != nil {
				if !strings.Contains(err.Error(), "transaction already exists") {
					log.Printf("DAG processing failed: %v", err)
				}
				continue
			}

			// Mark as processed
			bp.processedTxs.Store(tx.GetId(), true)

			// Then process through regular validation
			if err := bp.processTransaction(tx); err != nil {
				log.Printf("Transaction processing failed: %v", err)
				continue
			}
		}
	}(batch)
}

func (bp *BatchProcessor) processTransaction(tx *thrylos.Transaction) error {
	// Verify transaction
	if err := bp.node.VerifyAndProcessTransaction(tx); err != nil {
		return fmt.Errorf("transaction verification failed: %v", err)
	}

	// Validate addresses
	if err := bp.node.validateTransactionAddresses(&shared.Transaction{
		Sender:  tx.Sender,
		Outputs: ConvertProtoOutputs(tx.Outputs),
	}); err != nil {
		return fmt.Errorf("address validation failed: %v", err)
	}

	// Only add to pending if not yet confirmed in DAG
	confirmed, _ := bp.node.DAGManager.GetConfirmationStatus(tx.GetId())
	if !confirmed {
		if err := bp.node.AddPendingTransaction(tx); err != nil {
			return fmt.Errorf("failed to add to pending transactions: %v", err)
		}
	}

	// Update balances
	if err := bp.node.updateBalances(tx); err != nil {
		return fmt.Errorf("failed to update balances: %v", err)
	}

	return nil
}

// Extend Node's transaction handling methods
func (n *Node) ProcessIncomingTransaction(tx *thrylos.Transaction) error {
	// Check if already processed
	if _, exists := n.BatchProcessor.processedTxs.Load(tx.GetId()); exists {
		return nil // Already processed, not an error
	}

	// Process through DAG first
	if err := n.DAGManager.AddTransaction(tx); err != nil {
		if strings.Contains(err.Error(), "transaction already exists") {
			return nil // Already in DAG, not an error
		}
		return fmt.Errorf("failed to add transaction to DAG: %v", err)
	}

	// Then add to batch processor
	return n.AddTransactionToBatch(tx)
}

func (n *Node) GetTransactionStatus(txID string) (string, error) {
	// Check DAG confirmation first
	dagConfirmed, _ := n.DAGManager.GetConfirmationStatus(txID)
	if dagConfirmed {
		return "confirmed", nil
	}

	// Check pending pool
	if n.HasTransaction(txID) {
		return "pending", nil
	}

	return "unknown", fmt.Errorf("transaction not found")
}

func (n *Node) InitializeProcessors() {
	n.BatchProcessor = NewBatchProcessor(n)
	n.DAGManager = NewDAGManager(n)
}

// Modified AddPendingTransaction to use batch processing
func (node *Node) AddTransactionToBatch(tx *thrylos.Transaction) error {
	if tx == nil {
		return fmt.Errorf("cannot add nil transaction")
	}

	// Check if transaction already exists in either system
	if node.HasTransaction(tx.GetId()) {
		return fmt.Errorf("transaction already exists in pending pool")
	}

	confirmed, _ := node.DAGManager.GetConfirmationStatus(tx.GetId())
	if confirmed {
		return fmt.Errorf("transaction already confirmed in DAG")
	}

	return node.BatchProcessor.AddTransaction(tx)
}
