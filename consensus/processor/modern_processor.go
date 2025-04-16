package processor

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/types"
)

// // Error definitions
var (
	ErrTxAlreadyExists = errors.New("transaction already exists in the pool")
	ErrNilTransaction  = errors.New("cannot process nil transaction")
)

// ModernProcessor processes transactions in parallel using worker shards
type ModernProcessor struct {
	workerCount    int
	workers        []*txWorker
	processedTxs   sync.Map
	metrics        *ProcessorMetrics
	ctx            context.Context
	cancel         context.CancelFunc
	txQueues       []chan *thrylos.Transaction
	priorityQueues []chan *thrylos.Transaction
	workerPool     chan struct{}
	msgCh          chan types.Message
	DAGManager     *DAGManager
	txPool         types.TxPool
	txProcessor    *TransactionProcessorImpl
	balanceCache   sync.Map // For caching balances
}

// ProcessorMetrics tracks performance metrics
type ProcessorMetrics struct {
	processedCount    atomic.Int64
	totalLatency      atomic.Int64
	currentThroughput atomic.Int64
}

// txWorker handles transaction processing for a specific shard
type txWorker struct {
	id        int
	shardID   int
	processor *ModernProcessor
	metrics   *workerMetrics
}

// workerMetrics tracks per-worker metrics
type workerMetrics struct {
	processedTxs atomic.Int64
	totalLatency atomic.Int64
}

// NewModernProcessor creates a new transaction processor with multiple worker shards
func NewModernProcessor(txProcessor *TransactionProcessorImpl, txPool types.TxPool, dagManager *DAGManager) *ModernProcessor {
	ctx, cancel := context.WithCancel(context.Background())
	workerCount := runtime.NumCPU() * 2 // Or your desired count

	mp := &ModernProcessor{
		workerCount:    workerCount,
		ctx:            ctx,
		cancel:         cancel,
		metrics:        &ProcessorMetrics{},
		txQueues:       make([]chan *thrylos.Transaction, 12), // Assuming 12 shards
		priorityQueues: make([]chan *thrylos.Transaction, 12), // Assuming 12 shards
		workerPool:     make(chan struct{}, workerCount),
		msgCh:          make(chan types.Message, 100), // Channel for subscribed messages
		txProcessor:    txProcessor,
		txPool:         txPool,
		DAGManager:     dagManager,
	}

	// Initialize queues (assuming 12 shards)
	for i := 0; i < 12; i++ {
		mp.txQueues[i] = make(chan *thrylos.Transaction, 10000)
		mp.priorityQueues[i] = make(chan *thrylos.Transaction, 1000)
	}

	// Initialize workers
	mp.workers = make([]*txWorker, workerCount)
	for i := 0; i < workerCount; i++ {
		mp.workers[i] = &txWorker{
			id:        i,
			shardID:   i % 12, // Assign shard ID based on worker index
			processor: mp,
			metrics:   &workerMetrics{},
		}
	}

	// Subscribe to message types using the singleton getter
	// --- CHANGE HERE ---
	messageBus := types.GetGlobalMessageBus() // Use the canonical singleton getter
	// --- END CHANGE ---
	log.Printf("DEBUG: [NewModernProcessor] Subscribing to MessageBus instance at %p", messageBus) // Add log
	messageBus.Subscribe(types.ProcessTransaction, mp.msgCh)                                       // Keep if needed
	messageBus.Subscribe(types.UpdateProcessorState, mp.msgCh)                                     // Keep

	// Start message handler if ModernProcessor needs to react to bus messages
	log.Println("INFO: [ModernProcessor] Starting internal message handler goroutine...")
	go mp.handleMessages()

	return mp
}

// handleMessages processes incoming message bus messages
func (mp *ModernProcessor) handleMessages() {
	for msg := range mp.msgCh {
		switch msg.Type {
		case types.ProcessTransaction:
			mp.handleProcessTransaction(msg)
		case types.UpdateProcessorState:
			mp.handleUpdateState(msg)
		}
	}
}

// handleProcessTransaction handles transaction processing messages
func (mp *ModernProcessor) handleProcessTransaction(msg types.Message) {
	tx := msg.Data.(*thrylos.Transaction)
	err := mp.ProcessIncomingTransaction(tx)
	msg.ResponseCh <- types.Response{Error: err}
}

// handleUpdateState handles processor state update messages
func (mp *ModernProcessor) handleUpdateState(msg types.Message) {
	req := msg.Data.(types.UpdateProcessorStateRequest)

	// Update the processor's state based on the request
	mp.processedTxs.Store(req.TransactionID, req.State)

	// Log the state update
	log.Printf("Updated transaction %s state to: %s", req.TransactionID, req.State)

	// Send response
	msg.ResponseCh <- types.Response{
		Data: map[string]string{
			"status": "updated",
			"txId":   req.TransactionID,
			"state":  req.State,
		},
	}
}

// Start begins transaction processing
func (mp *ModernProcessor) Start() {
	log.Printf("Starting ModernProcessor with %d workers", mp.workerCount)

	// Start worker routines
	for _, worker := range mp.workers {
		go worker.start()
	}

	// Start metrics collection
	go mp.collectMetrics()
}

// Stop halts transaction processing
func (mp *ModernProcessor) Stop() {
	mp.cancel()
}

// ProcessIncomingTransaction handles a new transaction
func (mp *ModernProcessor) ProcessIncomingTransaction(tx *thrylos.Transaction) error {
	if tx == nil {
		log.Printf("ERROR: [ModernProcessor.ProcessIncomingTransaction] Received nil transaction")
		return ErrNilTransaction
	}

	txID := tx.GetId()
	log.Printf("=== BEGIN ModernProcessor.ProcessIncomingTransaction [%s] ===", txID)

	// Check processed status (remains the same)
	if status, exists := mp.processedTxs.Load(txID); exists {
		log.Printf("Transaction [%s] already processed/queued by ModernProcessor (Status: %v), skipping", txID, status)
		return nil
	}

	// --- DAG Processing ---
	log.Printf("Processing DAG for transaction [%s]", txID)
	responseCh := make(chan types.Response)
	// --- CHANGE HERE ---
	messageBus := types.GetGlobalMessageBus() // Use the canonical singleton getter
	// --- END CHANGE ---
	log.Printf("DEBUG: [ModernProcessor] Publishing ValidateDAGTx using MessageBus instance at %p", messageBus) // Keep log
	messageBus.Publish(types.Message{
		Type:       types.ValidateDAGTx,
		Data:       tx,
		ResponseCh: responseCh,
	})

	// Wait for DAG response (with timeout)
	select {
	case response := <-responseCh:
		// ... (handling of DAG response remains the same) ...
		if response.Error != nil {
			if !strings.Contains(response.Error.Error(), "already exists") {
				log.Printf("Warning: DAG processing check returned an error for [%s]: %v", txID, response.Error)
			} else {
				log.Printf("Transaction [%s] already exists in DAG (according to DAG manager response)", txID)
			}
		} else {
			log.Printf("DEBUG: DAG processing successful for [%s]", txID)
		}
	case <-time.After(5 * time.Second): // Keep or adjust timeout as needed
		log.Printf("ERROR: Timeout waiting for DAG processing response for [%s]", txID)
		return fmt.Errorf("timeout waiting for DAG processing response")
	}
	// --- End DAG Processing ---

	// --- *** Transaction Pool Add Logic is Correctly REMOVED *** ---

	// --- Status Update (Optional at this stage) ---
	updateStatusCh := make(chan types.Response)
	messageBus.Publish(types.Message{ // Use the same messageBus instance obtained above
		Type: types.UpdateProcessorState,
		Data: types.UpdateProcessorStateRequest{
			TransactionID: txID,
			State:         TxStatusProcessing, // Use constant if defined
		},
		ResponseCh: updateStatusCh,
	})
	// Non-blocking wait (remains the same)
	go func() {
		select {
		case statusResponse := <-updateStatusCh:
			if statusResponse.Error != nil {
				log.Printf("Warning: Error sending transaction status update via bus for [%s]: %v", txID, statusResponse.Error)
			} else {
				log.Printf("DEBUG: Status update '%s' sent to bus for [%s]", TxStatusProcessing, txID)
			}
		case <-time.After(2 * time.Second):
			log.Printf("Warning: Timeout waiting for status update ack for [%s]", txID)
		}
	}()
	// --- End Status Update ---

	// --- Clear Balance Cache --- (remains the same)
	mp.balanceCache.Delete(tx.Sender)
	for _, output := range tx.Outputs {
		mp.balanceCache.Delete(output.OwnerAddress)
	}

	// --- Queue for Internal Worker Processing --- (remains the same)
	log.Printf("Adding transaction [%s] to ModernProcessor worker queue", txID)
	if err := mp.AddTransaction(tx); err != nil {
		log.Printf("ERROR: Failed to queue transaction [%s] for worker: %v", txID, err)
		return fmt.Errorf("modern processing queue failed: %v", err)
	}

	// Mark as processed *by this initial stage* (remains the same)
	mp.processedTxs.Store(txID, "queued_for_worker")

	log.Printf("=== END ModernProcessor.ProcessIncomingTransaction [%s] - Queued for Worker ===", txID)
	return nil // Indicate success
}

// AddTransaction assigns a transaction to a processing shard
func (mp *ModernProcessor) AddTransaction(tx *thrylos.Transaction) error {
	txID := tx.GetId()
	log.Printf("[ModernProcessor] Starting transaction processing for %s", txID)

	if _, exists := mp.processedTxs.Load(txID); exists {
		log.Printf("[ModernProcessor] Transaction %s already processed", txID)
		return nil
	}

	shardID := mp.getShardID(tx)
	log.Printf("[ModernProcessor] Assigned transaction %s to shard %d", txID, shardID)

	// Try queue with timeout
	timeoutChan := make(chan bool, 1)
	successChan := make(chan bool, 1)

	go func() {
		select {
		case mp.txQueues[shardID] <- tx:
			mp.processedTxs.Store(txID, true)
			successChan <- true
		case <-time.After(2 * time.Second):
			timeoutChan <- true
		}
	}()

	select {
	case <-successChan:
		log.Printf("[ModernProcessor] Successfully queued transaction %s", txID)
		return nil
	case <-timeoutChan:
		log.Printf("[ModernProcessor] Queue timeout for transaction %s", txID)
		return fmt.Errorf("queue timeout for shard %d", shardID)
	}
}

// start begins the worker's processing loop
func (w *txWorker) start() {
	for {
		select {
		case <-w.processor.ctx.Done():
			return
		default:
			// Try to get a transaction from priority queue first
			select {
			case tx := <-w.processor.priorityQueues[w.shardID]:
				w.processTx(tx, true)
			default:
				// If no priority tx, try regular queue
				select {
				case tx := <-w.processor.txQueues[w.shardID]:
					w.processTx(tx, false)
				default:
					// No transactions available, small sleep to prevent CPU spin
					time.Sleep(time.Millisecond)
				}
			}
		}
	}
}

// processTx processes a single transaction
func (w *txWorker) processTx(tx *thrylos.Transaction, isPriority bool) {
	start := time.Now()
	txID := tx.GetId()

	// Get or create status
	statusIface, _ := w.processor.txProcessor.txStatusMap.LoadOrStore(txID, &TransactionStatus{})
	status := statusIface.(*TransactionStatus)

	status.Lock()
	if status.ProcessedByModern {
		status.Unlock()
		return
	}

	// Verify before marking as processed
	if err := w.processor.txProcessor.VerifyAndProcessTransaction(tx); err != nil {
		status.Unlock()
		log.Printf("Transaction processing failed: %v", err)
		w.processor.processedTxs.Delete(txID)
		// Clean up status on failure
		w.processor.txProcessor.txStatusMap.Delete(txID)
		return
	}

	status.ProcessedByModern = true

	// If DAG has confirmed, trigger processing
	if status.ConfirmedByDAG {
		status.Unlock()
		w.processor.txProcessor.handleProcessedTransaction(tx)
	} else {
		status.Unlock()
	}

	// Update metrics
	latency := time.Since(start)
	w.metrics.processedTxs.Add(1)
	w.metrics.totalLatency.Add(int64(latency))
}

// getShardID determines which shard should process a transaction
func (mp *ModernProcessor) getShardID(tx *thrylos.Transaction) int {
	// Use an FNV hash for better distribution
	h := fnv.New32a()
	h.Write([]byte(tx.GetId()))
	return int(h.Sum32() % uint32(12))
}

// collectMetrics gathers and updates processor metrics
func (mp *ModernProcessor) collectMetrics() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var lastProcessed int64
	for {
		select {
		case <-mp.ctx.Done():
			return
		case <-ticker.C:
			currentProcessed := mp.getTotalProcessed()
			throughput := currentProcessed - lastProcessed
			mp.metrics.currentThroughput.Store(throughput)
			lastProcessed = currentProcessed
		}
	}
}

// getTotalProcessed returns the total number of processed transactions
func (mp *ModernProcessor) getTotalProcessed() int64 {
	var total int64
	for _, worker := range mp.workers {
		total += worker.metrics.processedTxs.Load()
	}
	return total
}

// GetMetrics returns current processing metrics
func (mp *ModernProcessor) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"processed_count":    mp.getTotalProcessed(),
		"current_throughput": mp.metrics.currentThroughput.Load(),
		"worker_count":       mp.workerCount,
	}
}
