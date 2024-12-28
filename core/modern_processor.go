package core

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
)

type ModernProcessor struct {
	node           *Node
	workerCount    int
	workers        []*txWorker
	processedTxs   sync.Map
	metrics        *ProcessorMetrics
	ctx            context.Context
	cancel         context.CancelFunc
	txQueues       []chan *thrylos.Transaction // One queue per shard
	priorityQueues []chan *thrylos.Transaction // Priority queue per shard
	workerPool     chan struct{}               // Limit concurrent workers
}

type ProcessorMetrics struct {
	processedCount    atomic.Int64
	totalLatency      atomic.Int64
	currentThroughput atomic.Int64
}

type txWorker struct {
	id        int
	shardID   int
	processor *ModernProcessor
	metrics   *workerMetrics
}

type workerMetrics struct {
	processedTxs atomic.Int64
	totalLatency atomic.Int64
}

func NewModernProcessor(node *Node) *ModernProcessor {
	ctx, cancel := context.WithCancel(context.Background())
	workerCount := runtime.NumCPU() * 2 // Double the CPU count for optimal throughput

	mp := &ModernProcessor{
		node:           node,
		workerCount:    workerCount,
		ctx:            ctx,
		cancel:         cancel,
		metrics:        &ProcessorMetrics{},
		txQueues:       make([]chan *thrylos.Transaction, 12), // 12 shards
		priorityQueues: make([]chan *thrylos.Transaction, 12),
		workerPool:     make(chan struct{}, workerCount),
	}

	// Initialize queues
	for i := 0; i < 12; i++ {
		mp.txQueues[i] = make(chan *thrylos.Transaction, 10000)      // Large buffer per shard
		mp.priorityQueues[i] = make(chan *thrylos.Transaction, 1000) // Smaller buffer for priority
	}

	// Initialize workers
	mp.workers = make([]*txWorker, workerCount)
	for i := 0; i < workerCount; i++ {
		mp.workers[i] = &txWorker{
			id:        i,
			shardID:   i % 12, // Distribute workers across shards
			processor: mp,
			metrics:   &workerMetrics{},
		}
	}

	return mp
}

func (mp *ModernProcessor) Start() {
	log.Printf("Starting ModernProcessor with %d workers", mp.workerCount)

	// Start worker routines
	for _, worker := range mp.workers {
		go worker.start()
	}

	// Start metrics collection
	go mp.collectMetrics()
}

func (mp *ModernProcessor) Stop() {
	mp.cancel()
}

func (n *Node) InitializeProcessors() {
	log.Printf("Initializing node processors...")

	// Initialize DAG Manager first
	n.DAGManager = NewDAGManager(n)
	log.Printf("DAG manager initialized")

	// Initialize ModernProcessor
	n.ModernProcessor = NewModernProcessor(n)
	n.ModernProcessor.Start()
	log.Printf("Modern processor initialized and started")

	log.Printf("Node processors initialization complete")
}

func (n *Node) ProcessIncomingTransaction(tx *thrylos.Transaction) error {
	if tx == nil {
		log.Printf("ERROR: Received nil transaction")
		return fmt.Errorf("cannot process nil transaction")
	}

	txID := tx.GetId()
	log.Printf("=== BEGIN ProcessIncomingTransaction [%s] ===", txID)

	// Fast path: check processed state
	if _, exists := n.ModernProcessor.processedTxs.Load(txID); exists {
		log.Printf("Transaction [%s] already processed, skipping", txID)
		return nil
	}

	// Process DAG first
	log.Printf("Processing DAG for transaction [%s]", txID)
	if err := n.DAGManager.AddTransaction(tx); err != nil {
		if !strings.Contains(err.Error(), "transaction already exists") {
			log.Printf("ERROR: DAG processing failed for [%s]: %v", txID, err)
			return fmt.Errorf("DAG processing failed: %v", err)
		}
		log.Printf("Transaction [%s] already exists in DAG", txID)
	}

	// Add to pending pool
	log.Printf("Adding to pending pool [%s]", txID)
	if err := n.AddPendingTransaction(tx); err != nil {
		log.Printf("ERROR: Failed to add [%s] to pending pool: %v", txID, err)
		return fmt.Errorf("pending addition failed: %v", err)
	}

	// Process through ModernProcessor
	log.Printf("Adding to ModernProcessor [%s]", txID)
	if err := n.ModernProcessor.AddTransaction(tx); err != nil {
		log.Printf("ERROR: ModernProcessor failed for [%s]: %v", txID, err)
		return fmt.Errorf("modern processing failed: %v", err)
	}

	log.Printf("=== END ProcessIncomingTransaction [%s] - SUCCESS ===", txID)
	return nil
}

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

func (w *txWorker) processTx(tx *thrylos.Transaction, isPriority bool) {
	start := time.Now()

	// Mark as being processed
	if _, exists := w.processor.processedTxs.LoadOrStore(tx.GetId(), true); exists {
		return
	}

	// Get worker slot
	w.processor.workerPool <- struct{}{}
	defer func() { <-w.processor.workerPool }()

	// Verify and process transaction
	if err := w.processor.node.VerifyAndProcessTransaction(tx); err != nil {
		log.Printf("Transaction processing failed: %v", err)
		w.processor.processedTxs.Delete(tx.GetId())
		return
	}

	// Update metrics
	latency := time.Since(start)
	w.metrics.processedTxs.Add(1)
	w.metrics.totalLatency.Add(int64(latency))

	// Handle processed transaction updates
	w.processor.node.handleProcessedTransaction(tx)

	if isPriority {
		// Trigger block creation for priority transactions
		select {
		case w.processor.node.BlockTrigger <- struct{}{}:
		default:
		}
	}
}

func (mp *ModernProcessor) getShardID(tx *thrylos.Transaction) int {
	// Use an FNV hash for better distribution
	h := fnv.New32a()
	h.Write([]byte(tx.GetId()))
	return int(h.Sum32() % uint32(12))
}

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
