package core

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

type BlockProducerConfig struct {
	TargetBlockTime   time.Duration
	MinTransactions   int
	MaxTransactions   int
	MaxBlockSize      int64
	NetworkLoadFactor float64
}

type ModernBlockProducer struct {
	config        *BlockProducerConfig
	node          *Node
	blockchain    *Blockchain
	isProducing   atomic.Bool
	lastBlockTime time.Time
	mu            sync.RWMutex
}

func NewBlockProducer(node *Node, blockchain *Blockchain) *ModernBlockProducer {
	return &ModernBlockProducer{
		config: &BlockProducerConfig{
			TargetBlockTime:   1200 * time.Millisecond, // 1.2s
			MinTransactions:   1,
			MaxTransactions:   1000,
			MaxBlockSize:      1 << 20, // 1MB
			NetworkLoadFactor: 1.0,
		},
		node:          node,
		blockchain:    blockchain,
		lastBlockTime: time.Now(),
	}
}

func (bp *ModernBlockProducer) Start() {
	log.Printf("Starting block producer with target block time: %v", bp.config.TargetBlockTime)

	ticker := time.NewTicker(bp.config.TargetBlockTime)
	go func() {
		for range ticker.C {
			if !bp.shouldProduceBlock() {
				continue
			}
			bp.tryProduceBlock()
		}
	}()
}

func (bp *ModernBlockProducer) shouldProduceBlock() bool {
	if bp.isProducing.Load() {
		return false
	}

	bp.mu.RLock()
	timeSinceLastBlock := time.Since(bp.lastBlockTime)
	bp.mu.RUnlock()

	bp.blockchain.Mu.RLock()
	pendingCount := len(bp.blockchain.PendingTransactions)
	bp.blockchain.Mu.RUnlock()

	log.Printf("Block production check: Time since last block: %v, Pending transactions: %d",
		timeSinceLastBlock, pendingCount)

	return timeSinceLastBlock >= bp.config.TargetBlockTime &&
		pendingCount >= bp.config.MinTransactions
}

func (bp *ModernBlockProducer) tryProduceBlock() {
	if !bp.isProducing.CompareAndSwap(false, true) {
		return
	}
	defer bp.isProducing.Store(false)

	validator := bp.blockchain.GetCurrentValidator()
	log.Printf("Attempting to produce block with validator: %s", validator)

	newBlock, err := bp.blockchain.ProcessPendingTransactions(validator)
	if err != nil {
		log.Printf("Error creating new block: %v", err)
		return
	}

	if newBlock != nil {
		bp.mu.Lock()
		bp.lastBlockTime = time.Now()
		bp.mu.Unlock()

		log.Printf("Successfully created block at %v with %d transactions",
			bp.lastBlockTime.Format(time.RFC3339), len(newBlock.Transactions))
	}
}

func (bp *ModernBlockProducer) Stop() {
	bp.isProducing.Store(false)
}
