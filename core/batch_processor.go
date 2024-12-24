package core

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
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
	currentBatch      []*thrylos.Transaction
	processedTxs      sync.Map                  // Track processed transaction IDs
	batchPool         sync.Pool                 // Reuse batch slices
	workerPool        chan struct{}             // Limit concurrent workers
	highPriorityQueue chan *thrylos.Transaction // Fast path for high-priority txs

}

func NewBatchProcessor(node *Node) *BatchProcessor {
	bp := &BatchProcessor{
		node:              node,
		batchQueue:        make(chan *thrylos.Transaction, BatchSize*MaxConcurrentBatch),
		currentBatch:      make([]*thrylos.Transaction, 0, BatchSize),
		highPriorityQueue: make(chan *thrylos.Transaction, BatchSize), // Fast path
		workerPool:        make(chan struct{}, runtime.NumCPU()),      // Limit concurrent workers
		batchPool: sync.Pool{
			New: func() interface{} {
				return make([]*thrylos.Transaction, 0, BatchSize)
			},
		},
	}

	go bp.batchManager()
	return bp
}

func (bp *BatchProcessor) AddTransaction(tx *thrylos.Transaction) error {
	// Try high-priority queue first
	select {
	case bp.highPriorityQueue <- tx:
		return nil
	default:
		// Fall back to normal queue
		select {
		case bp.batchQueue <- tx:
			return nil
		default:
			return fmt.Errorf("batch queue is full")
		}
	}
}

func (bp *BatchProcessor) batchManager() {
	ticker := time.NewTicker(100 * time.Millisecond) // More frequent checks
	defer ticker.Stop()

	for {
		select {
		case tx := <-bp.highPriorityQueue:
			// Fast path for high-priority transactions
			bp.processSingleTransaction(tx)

		case tx := <-bp.batchQueue:
			batch := bp.currentBatch
			batch = append(batch, tx)

			if len(batch) >= BatchSize {
				bp.processBatchAsync(batch)
				bp.currentBatch = bp.batchPool.Get().([]*thrylos.Transaction)
			} else {
				bp.currentBatch = batch
			}

		case <-ticker.C:
			if len(bp.currentBatch) >= MinBatchSize {
				bp.processBatchAsync(bp.currentBatch)
				bp.currentBatch = bp.batchPool.Get().([]*thrylos.Transaction)
			}
		}
	}
}

func (bp *BatchProcessor) processBatchAsync(batch []*thrylos.Transaction) {
	// Get worker slot
	bp.workerPool <- struct{}{}

	bp.processingBatches.Add(1)
	go func(transactions []*thrylos.Transaction) {
		defer func() {
			bp.processingBatches.Done()
			<-bp.workerPool                    // Release worker slot
			bp.batchPool.Put(transactions[:0]) // Return slice to pool
		}()

		// Process in smaller chunks for better concurrency
		chunkSize := 20
		for i := 0; i < len(transactions); i += chunkSize {
			end := i + chunkSize
			if end > len(transactions) {
				end = len(transactions)
			}

			var wg sync.WaitGroup
			for _, tx := range transactions[i:end] {
				wg.Add(1)
				go func(transaction *thrylos.Transaction) {
					defer wg.Done()
					bp.processTransaction(transaction)
				}(tx)
			}
			wg.Wait()
		}
	}(batch)
}

func (bp *BatchProcessor) processSingleTransaction(tx *thrylos.Transaction) {
	if _, exists := bp.processedTxs.Load(tx.GetId()); exists {
		return
	}

	// Fast path processing
	if err := bp.node.DAGManager.AddTransaction(tx); err == nil {
		bp.processedTxs.Store(tx.GetId(), true)
		bp.processTransaction(tx)
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
	log.Printf("BatchProcessor processing transaction %s", tx.GetId())

	if _, exists := bp.processedTxs.Load(tx.GetId()); exists {
		log.Printf("Transaction %s already processed by batch processor", tx.GetId())
		return nil
	}

	// Verify transaction
	if err := bp.node.VerifyAndProcessTransaction(tx); err != nil {
		log.Printf("Transaction verification failed for %s: %v", tx.GetId(), err)
		return err
	}

	// Mark as processed
	bp.processedTxs.Store(tx.GetId(), true)
	log.Printf("BatchProcessor completed processing transaction %s", tx.GetId())
	return nil
}

// Extend Node's transaction handling methods
func (n *Node) ProcessIncomingTransaction(tx *thrylos.Transaction) error {
	log.Printf("Starting ProcessIncomingTransaction for tx %s", tx.GetId())

	// Check if already processed
	if _, exists := n.BatchProcessor.processedTxs.Load(tx.GetId()); exists {
		log.Printf("Transaction %s already processed", tx.GetId())
		return nil
	}

	// Process through DAG first
	log.Printf("Adding transaction %s to DAG", tx.GetId())
	if err := n.DAGManager.AddTransaction(tx); err != nil {
		if !strings.Contains(err.Error(), "transaction already exists") {
			log.Printf("DAG processing failed for tx %s: %v", tx.GetId(), err)
			return fmt.Errorf("DAG processing failed: %v", err)
		}
		log.Printf("Transaction %s already exists in DAG", tx.GetId())
	}

	// Add to batch processor
	log.Printf("Adding transaction %s to batch processor", tx.GetId())
	if err := n.BatchProcessor.AddTransaction(tx); err != nil {
		log.Printf("Batch processing failed for tx %s: %v", tx.GetId(), err)
		return fmt.Errorf("batch processing failed: %v", err)
	}

	// Still need direct pending addition for immediate status updates
	log.Printf("Adding transaction %s to pending pool", tx.GetId())
	if err := n.AddPendingTransaction(tx); err != nil {
		log.Printf("Failed to add tx %s to pending pool: %v", tx.GetId(), err)
		return fmt.Errorf("pending addition failed: %v", err)
	}

	log.Printf("Successfully processed incoming transaction %s", tx.GetId())
	return nil
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
	log.Printf("Initializing node processors...")

	n.BatchProcessor = NewBatchProcessor(n)
	log.Printf("Batch processor initialized")

	n.DAGManager = NewDAGManager(n)
	log.Printf("DAG manager initialized")

	// ProcessIncomingTransaction is a method, doesn't need initialization
	log.Printf("Node processors initialization complete")
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
