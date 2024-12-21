package core

import (
	"fmt"
	"log"
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

		// Process transactions in parallel with bounded concurrency
		semaphore := make(chan struct{}, MaxConcurrentBatch)
		var wg sync.WaitGroup

		for _, tx := range transactions {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore

			go func(transaction *thrylos.Transaction) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore

				if err := bp.processTransaction(transaction); err != nil {
					log.Printf("Error processing transaction %s: %v", transaction.GetId(), err)
					return
				}
			}(tx)
		}

		wg.Wait()
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

	// Add to pending transactions
	if err := bp.node.AddPendingTransaction(tx); err != nil {
		return fmt.Errorf("failed to add to pending transactions: %v", err)
	}

	// Update balances
	if err := bp.node.updateBalances(tx); err != nil {
		return fmt.Errorf("failed to update balances: %v", err)
	}

	return nil
}

// Extend Node struct to include BatchProcessor
func (n *Node) InitializeBatchProcessor() {
	n.BatchProcessor = NewBatchProcessor(n)
}

// Modified AddPendingTransaction to use batch processing
func (node *Node) AddTransactionToBatch(tx *thrylos.Transaction) error {
	if tx == nil {
		return fmt.Errorf("cannot add nil transaction")
	}

	// Check if transaction already exists
	if node.HasTransaction(tx.GetId()) {
		return fmt.Errorf("transaction already exists")
	}

	return node.BatchProcessor.AddTransaction(tx)
}
