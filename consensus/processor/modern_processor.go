package processor

// // Error definitions
// var (
// 	ErrTxAlreadyExists = errors.New("transaction already exists in the pool")
// 	ErrNilTransaction  = errors.New("cannot process nil transaction")
// )

// // ModernProcessor processes transactions in parallel using worker shards
// type ModernProcessor struct {
// 	workerCount    int
// 	workers        []*txWorker
// 	processedTxs   sync.Map
// 	metrics        *ProcessorMetrics
// 	ctx            context.Context
// 	cancel         context.CancelFunc
// 	txQueues       []chan *thrylos.Transaction
// 	priorityQueues []chan *thrylos.Transaction
// 	workerPool     chan struct{}
// 	msgCh          chan types.Message
// 	DAGManager     *DAGManager
// 	txPool         types.TxPool
// 	txProcessor    *TransactionProcessorImpl
// 	balanceCache   sync.Map // For caching balances
// }

// // ProcessorMetrics tracks performance metrics
// type ProcessorMetrics struct {
// 	processedCount    atomic.Int64
// 	totalLatency      atomic.Int64
// 	currentThroughput atomic.Int64
// }

// // txWorker handles transaction processing for a specific shard
// type txWorker struct {
// 	id        int
// 	shardID   int
// 	processor *ModernProcessor
// 	metrics   *workerMetrics
// }

// // workerMetrics tracks per-worker metrics
// type workerMetrics struct {
// 	processedTxs atomic.Int64
// 	totalLatency atomic.Int64
// }

// // NewModernProcessor creates a new transaction processor with multiple worker shards
// func NewModernProcessor(txProcessor *TransactionProcessorImpl, txPool types.TxPool, dagManager *DAGManager) *ModernProcessor {
// 	ctx, cancel := context.WithCancel(context.Background())
// 	workerCount := runtime.NumCPU() * 2

// 	mp := &ModernProcessor{
// 		workerCount:    workerCount,
// 		ctx:            ctx,
// 		cancel:         cancel,
// 		metrics:        &ProcessorMetrics{},
// 		txQueues:       make([]chan *thrylos.Transaction, 12),
// 		priorityQueues: make([]chan *thrylos.Transaction, 12),
// 		workerPool:     make(chan struct{}, workerCount),
// 		msgCh:          make(chan types.Message, 100),
// 		txProcessor:    txProcessor,
// 		txPool:         txPool,
// 		DAGManager:     dagManager,
// 	}

// 	// Initialize queues
// 	for i := 0; i < 12; i++ {
// 		mp.txQueues[i] = make(chan *thrylos.Transaction, 10000)
// 		mp.priorityQueues[i] = make(chan *thrylos.Transaction, 1000)
// 	}

// 	// Initialize workers
// 	mp.workers = make([]*txWorker, workerCount)
// 	for i := 0; i < workerCount; i++ {
// 		mp.workers[i] = &txWorker{
// 			id:        i,
// 			shardID:   i % 12,
// 			processor: mp,
// 			metrics:   &workerMetrics{},
// 		}
// 	}

// 	// Subscribe to message types
// 	messageBus := shared.GetMessageBus()
// 	messageBus.Subscribe(types.ProcessTransaction, mp.msgCh)
// 	messageBus.Subscribe(types.UpdateProcessorState, mp.msgCh)

// 	// Start message handler
// 	go mp.handleMessages()

// 	return mp
// }

// // handleMessages processes incoming message bus messages
// func (mp *ModernProcessor) handleMessages() {
// 	for msg := range mp.msgCh {
// 		switch msg.Type {
// 		case types.ProcessTransaction:
// 			mp.handleProcessTransaction(msg)
// 		case types.UpdateProcessorState:
// 			mp.handleUpdateState(msg)
// 		}
// 	}
// }

// // handleProcessTransaction handles transaction processing messages
// func (mp *ModernProcessor) handleProcessTransaction(msg types.Message) {
// 	tx := msg.Data.(*thrylos.Transaction)
// 	err := mp.ProcessIncomingTransaction(tx)
// 	msg.ResponseCh <- types.Response{Error: err}
// }

// // handleUpdateState handles processor state update messages
// func (mp *ModernProcessor) handleUpdateState(msg types.Message) {
// 	req := msg.Data.(types.UpdateProcessorStateRequest)

// 	// Update the processor's state based on the request
// 	mp.processedTxs.Store(req.TransactionID, req.State)

// 	// Log the state update
// 	log.Printf("Updated transaction %s state to: %s", req.TransactionID, req.State)

// 	// Send response
// 	msg.ResponseCh <- types.Response{
// 		Data: map[string]string{
// 			"status": "updated",
// 			"txId":   req.TransactionID,
// 			"state":  req.State,
// 		},
// 	}
// }

// // Start begins transaction processing
// func (mp *ModernProcessor) Start() {
// 	log.Printf("Starting ModernProcessor with %d workers", mp.workerCount)

// 	// Start worker routines
// 	for _, worker := range mp.workers {
// 		go worker.start()
// 	}

// 	// Start metrics collection
// 	go mp.collectMetrics()
// }

// // Stop halts transaction processing
// func (mp *ModernProcessor) Stop() {
// 	mp.cancel()
// }

// // ProcessIncomingTransaction handles a new transaction
// func (mp *ModernProcessor) ProcessIncomingTransaction(tx *thrylos.Transaction) error {
// 	if tx == nil {
// 		log.Printf("ERROR: Received nil transaction")
// 		return ErrNilTransaction
// 	}

// 	txID := tx.GetId()
// 	log.Printf("=== BEGIN ProcessIncomingTransaction [%s] ===", txID)

// 	// Fast path: check processed state
// 	if _, exists := mp.processedTxs.Load(txID); exists {
// 		log.Printf("Transaction [%s] already processed, skipping", txID)
// 		return nil
// 	}

// 	// Process DAG first using message system
// 	log.Printf("Processing DAG for transaction [%s]", txID)
// 	responseCh := make(chan types.Response)
// 	shared.GetMessageBus().Publish(types.Message{
// 		Type:       types.ValidateDAGTx,
// 		Data:       tx,
// 		ResponseCh: responseCh,
// 	})

// 	// Wait for DAG response
// 	response := <-responseCh
// 	if response.Error != nil {
// 		if !strings.Contains(response.Error.Error(), "transaction already exists") {
// 			log.Printf("ERROR: DAG processing failed for [%s]: %v", txID, response.Error)
// 			return fmt.Errorf("DAG processing failed: %v", response.Error)
// 		}
// 		log.Printf("Transaction [%s] already exists in DAG", txID)
// 	}

// 	// Convert thrylos.Transaction to types.Transaction
// 	// You need to implement this conversion function
// 	typeTx := ThrylosToShared(tx)

// 	// Add to transaction pool
// 	log.Printf("Adding to transaction pool [%s]", txID)
// 	if err := mp.txPool.AddTransaction(typeTx); err != nil {
// 		if !errors.Is(err, ErrTxAlreadyExists) {
// 			log.Printf("ERROR: Failed to add [%s] to transaction pool: %v", txID, err)
// 			return fmt.Errorf("pool addition failed: %v", err)
// 		}
// 		log.Printf("Transaction [%s] already exists in pool", txID)
// 	}

// 	// Update transaction status - using message bus for node communication
// 	// We need to use a message type that exists in your types package
// 	updateStatusCh := make(chan types.Response)
// 	shared.GetMessageBus().Publish(types.Message{
// 		Type: types.UpdateProcessorState,
// 		Data: types.UpdateProcessorStateRequest{
// 			TransactionID: txID,
// 			State:         "pending", // Use TxStatusPending constant in production
// 		},
// 		ResponseCh: updateStatusCh,
// 	})

// 	// We can optionally wait for the status update confirmation
// 	statusResponse := <-updateStatusCh
// 	if statusResponse.Error != nil {
// 		log.Printf("Warning: Error updating transaction status: %v", statusResponse.Error)
// 	}

// 	// Check pool size and trigger block creation if needed
// 	poolSize := mp.txPool.Size()
// 	if poolSize == 1 {
// 		// Trigger block creation using message bus
// 		triggerCh := make(chan types.Response)
// 		shared.GetMessageBus().Publish(types.Message{
// 			Type:       types.ProcessBlock,
// 			Data:       nil, // No specific data needed, just triggering block creation
// 			ResponseCh: triggerCh,
// 		})
// 		// Optionally wait for response
// 		<-triggerCh
// 	}

// 	// Clear balance cache using the local cache
// 	mp.balanceCache.Delete(tx.Sender)
// 	for _, output := range tx.Outputs {
// 		mp.balanceCache.Delete(output.OwnerAddress)
// 	}

// 	// Process through ModernProcessor
// 	log.Printf("Adding to ModernProcessor [%s]", txID)
// 	if err := mp.AddTransaction(tx); err != nil {
// 		// Use the converted transaction for removal
// 		mp.txPool.RemoveTransaction(typeTx)
// 		log.Printf("ERROR: ModernProcessor failed for [%s]: %v", txID, err)
// 		return fmt.Errorf("modern processing failed: %v", err)
// 	}

// 	log.Printf("=== END ProcessIncomingTransaction [%s] - SUCCESS ===", txID)
// 	return nil
// }

// // AddTransaction assigns a transaction to a processing shard
// func (mp *ModernProcessor) AddTransaction(tx *thrylos.Transaction) error {
// 	txID := tx.GetId()
// 	log.Printf("[ModernProcessor] Starting transaction processing for %s", txID)

// 	if _, exists := mp.processedTxs.Load(txID); exists {
// 		log.Printf("[ModernProcessor] Transaction %s already processed", txID)
// 		return nil
// 	}

// 	shardID := mp.getShardID(tx)
// 	log.Printf("[ModernProcessor] Assigned transaction %s to shard %d", txID, shardID)

// 	// Try queue with timeout
// 	timeoutChan := make(chan bool, 1)
// 	successChan := make(chan bool, 1)

// 	go func() {
// 		select {
// 		case mp.txQueues[shardID] <- tx:
// 			mp.processedTxs.Store(txID, true)
// 			successChan <- true
// 		case <-time.After(2 * time.Second):
// 			timeoutChan <- true
// 		}
// 	}()

// 	select {
// 	case <-successChan:
// 		log.Printf("[ModernProcessor] Successfully queued transaction %s", txID)
// 		return nil
// 	case <-timeoutChan:
// 		log.Printf("[ModernProcessor] Queue timeout for transaction %s", txID)
// 		return fmt.Errorf("queue timeout for shard %d", shardID)
// 	}
// }

// // start begins the worker's processing loop
// func (w *txWorker) start() {
// 	for {
// 		select {
// 		case <-w.processor.ctx.Done():
// 			return
// 		default:
// 			// Try to get a transaction from priority queue first
// 			select {
// 			case tx := <-w.processor.priorityQueues[w.shardID]:
// 				w.processTx(tx, true)
// 			default:
// 				// If no priority tx, try regular queue
// 				select {
// 				case tx := <-w.processor.txQueues[w.shardID]:
// 					w.processTx(tx, false)
// 				default:
// 					// No transactions available, small sleep to prevent CPU spin
// 					time.Sleep(time.Millisecond)
// 				}
// 			}
// 		}
// 	}
// }

// // processTx processes a single transaction
// func (w *txWorker) processTx(tx *thrylos.Transaction, isPriority bool) {
// 	start := time.Now()
// 	txID := tx.GetId()

// 	// Get or create status
// 	statusIface, _ := w.processor.txProcessor.txStatusMap.LoadOrStore(txID, &TransactionStatus{})
// 	status := statusIface.(*TransactionStatus)

// 	status.Lock()
// 	if status.ProcessedByModern {
// 		status.Unlock()
// 		return
// 	}

// 	// Verify before marking as processed
// 	if err := w.processor.txProcessor.VerifyAndProcessTransaction(tx); err != nil {
// 		status.Unlock()
// 		log.Printf("Transaction processing failed: %v", err)
// 		w.processor.processedTxs.Delete(txID)
// 		// Clean up status on failure
// 		w.processor.txProcessor.txStatusMap.Delete(txID)
// 		return
// 	}

// 	status.ProcessedByModern = true

// 	// If DAG has confirmed, trigger processing
// 	if status.ConfirmedByDAG {
// 		status.Unlock()
// 		w.processor.txProcessor.handleProcessedTransaction(tx)
// 	} else {
// 		status.Unlock()
// 	}

// 	// Update metrics
// 	latency := time.Since(start)
// 	w.metrics.processedTxs.Add(1)
// 	w.metrics.totalLatency.Add(int64(latency))
// }

// // getShardID determines which shard should process a transaction
// func (mp *ModernProcessor) getShardID(tx *thrylos.Transaction) int {
// 	// Use an FNV hash for better distribution
// 	h := fnv.New32a()
// 	h.Write([]byte(tx.GetId()))
// 	return int(h.Sum32() % uint32(12))
// }

// // collectMetrics gathers and updates processor metrics
// func (mp *ModernProcessor) collectMetrics() {
// 	ticker := time.NewTicker(time.Second)
// 	defer ticker.Stop()

// 	var lastProcessed int64
// 	for {
// 		select {
// 		case <-mp.ctx.Done():
// 			return
// 		case <-ticker.C:
// 			currentProcessed := mp.getTotalProcessed()
// 			throughput := currentProcessed - lastProcessed
// 			mp.metrics.currentThroughput.Store(throughput)
// 			lastProcessed = currentProcessed
// 		}
// 	}
// }

// // getTotalProcessed returns the total number of processed transactions
// func (mp *ModernProcessor) getTotalProcessed() int64 {
// 	var total int64
// 	for _, worker := range mp.workers {
// 		total += worker.metrics.processedTxs.Load()
// 	}
// 	return total
// }

// // GetMetrics returns current processing metrics
// func (mp *ModernProcessor) GetMetrics() map[string]interface{} {
// 	return map[string]interface{}{
// 		"processed_count":    mp.getTotalProcessed(),
// 		"current_throughput": mp.metrics.currentThroughput.Load(),
// 		"worker_count":       mp.workerCount,
// 	}
// }
