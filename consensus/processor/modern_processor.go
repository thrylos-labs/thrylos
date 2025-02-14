package processor

// With the modern processor transactions are assigned to workers (parallel processors) each worker processes transactions in a specific shard, which makes it more scalable.

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
// }

// type ProcessorMetrics struct {
// 	processedCount    atomic.Int64
// 	totalLatency      atomic.Int64
// 	currentThroughput atomic.Int64
// }

// type txWorker struct {
// 	id        int
// 	shardID   int
// 	processor *ModernProcessor
// 	metrics   *workerMetrics
// }

// type workerMetrics struct {
// 	processedTxs atomic.Int64
// 	totalLatency atomic.Int64
// }

// func NewModernProcessor() *ModernProcessor {
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

// func (mp *ModernProcessor) handleProcessTransaction(msg types.Message) {
// 	tx := msg.Data.(*thrylos.Transaction)
// 	err := mp.ProcessIncomingTransaction(tx)
// 	msg.ResponseCh <- types.Response{Error: err}
// }

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

// func (mp *ModernProcessor) Start() {
// 	log.Printf("Starting ModernProcessor with %d workers", mp.workerCount)

// 	// Start worker routines
// 	for _, worker := range mp.workers {
// 		go worker.start()
// 	}

// 	// Start metrics collection
// 	go mp.collectMetrics()
// }

// func (mp *ModernProcessor) Stop() {
// 	mp.cancel()
// }

// func (mp *ModernProcessor) ProcessIncomingTransaction(dagManager *DAGManager, tx *thrylos.Transaction) error {
// 	if tx == nil {
// 		log.Printf("ERROR: Received nil transaction")
// 		return fmt.Errorf("cannot process nil transaction")
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

// 	// Add to transaction pool
// 	log.Printf("Adding to transaction pool [%s]", txID)
// 	if err := node.blockchain.txPool.AddTransaction(tx); err != nil {
// 		if !errors.Is(err, ErrTxAlreadyExists) {
// 			log.Printf("ERROR: Failed to add [%s] to transaction pool: %v", txID, err)
// 			return fmt.Errorf("pool addition failed: %v", err)
// 		}
// 		log.Printf("Transaction [%s] already exists in pool", txID)
// 	}

// 	// Update transaction status
// 	if err := node.Blockchain.UpdateTransactionStatus(tx.Id, TxStatusPending, nil); err != nil {
// 		log.Printf("Warning: Error updating transaction status: %v", err)
// 	}

// 	// Check pool size and trigger block creation if needed
// 	poolSize := node.blockchain.txPool.Size()
// 	if poolSize == 1 {
// 		go node.TriggerBlockCreation()
// 	}

// 	// Clear balance cache
// 	balanceCache.Delete(tx.Sender)
// 	for _, output := range tx.Outputs {
// 		balanceCache.Delete(output.OwnerAddress)
// 	}

// 	// Process through ModernProcessor
// 	log.Printf("Adding to ModernProcessor [%s]", txID)
// 	if err := mp.AddTransaction(tx); err != nil {
// 		mp.txPool.RemoveTransaction(tx)
// 		log.Printf("ERROR: ModernProcessor failed for [%s]: %v", txID, err)
// 		return fmt.Errorf("modern processing failed: %v", err)
// 	}

// 	log.Printf("=== END ProcessIncomingTransaction [%s] - SUCCESS ===", txID)
// 	return nil
// }

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

// func (w *txWorker) processTx(tx *thrylos.Transaction, isPriority bool) {
// 	start := time.Now()
// 	txID := tx.GetId()

// 	// Get or create status
// 	statusIface, _ := w.processor.node.txStatusMap.LoadOrStore(txID, &TransactionStatus{})
// 	status := statusIface.(*TransactionStatus)

// 	status.Lock()
// 	if status.ProcessedByModern {
// 		status.Unlock()
// 		return
// 	}

// 	// Verify before marking as processed
// 	if err := w.processor.node.VerifyAndProcessTransaction(tx); err != nil {
// 		status.Unlock()
// 		log.Printf("Transaction processing failed: %v", err)
// 		w.processor.processedTxs.Delete(txID)
// 		// Clean up status on failure
// 		w.processor.node.txStatusMap.Delete(txID)
// 		return
// 	}

// 	status.ProcessedByModern = true

// 	// If DAG has confirmed, trigger processing
// 	if status.ConfirmedByDAG {
// 		status.Unlock()
// 		w.processor.node.handleProcessedTransaction(tx)
// 	} else {
// 		status.Unlock()
// 	}

// 	// Update metrics
// 	latency := time.Since(start)
// 	w.metrics.processedTxs.Add(1)
// 	w.metrics.totalLatency.Add(int64(latency))
// }

// func (mp *ModernProcessor) getShardID(tx *thrylos.Transaction) int {
// 	// Use an FNV hash for better distribution
// 	h := fnv.New32a()
// 	h.Write([]byte(tx.GetId()))
// 	return int(h.Sum32() % uint32(12))
// }

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
