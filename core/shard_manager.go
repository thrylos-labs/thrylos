package core

import (
	"sync"
	"time"
)

const (
	MinShardsCount        = 1
	MaxShardsCount        = 100
	OptimalNodesPerShard  = 10
	OptimalTxPerShard     = 1000
	ShardAdjustmentPeriod = 5 * time.Minute
)

type ShardManager struct {
	Shards  []*Shard
	mutex   sync.RWMutex
	network *Network // Placeholder for network information
}

func NewShardManager(network *Network) *ShardManager {
	sm := &ShardManager{
		Shards:  make([]*Shard, MinShardsCount),
		network: network,
	}
	for i := 0; i < MinShardsCount; i++ {
		sm.Shards[i] = NewShard(i, OptimalNodesPerShard)
	}
	go sm.periodicShardAdjustment()
	return sm
}

func (sm *ShardManager) periodicShardAdjustment() {
	ticker := time.NewTicker(ShardAdjustmentPeriod)
	for range ticker.C {
		sm.adjustShards()
	}
}

func (sm *ShardManager) adjustShards() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	totalNodes := sm.network.GetTotalNodeCount()
	totalTx := sm.network.GetTotalPendingTransactions()

	optimalShardCount := max(
		MinShardsCount,
		min(
			MaxShardsCount,
			max(
				totalNodes/OptimalNodesPerShard,
				totalTx/OptimalTxPerShard,
			),
		),
	)

	currentShardCount := len(sm.Shards)

	if optimalShardCount > currentShardCount {
		sm.increaseShardsCount(optimalShardCount - currentShardCount)
	} else if optimalShardCount < currentShardCount {
		sm.decreaseShardsCount(currentShardCount - optimalShardCount)
	}
}

func (sm *ShardManager) increaseShardsCount(count int) {
	for i := 0; i < count; i++ {
		newShard := NewShard(len(sm.Shards), OptimalNodesPerShard)
		sm.Shards = append(sm.Shards, newShard)
	}
	sm.rebalanceNodes()
}

func (sm *ShardManager) decreaseShardsCount(count int) {
	if len(sm.Shards)-count < MinShardsCount {
		count = len(sm.Shards) - MinShardsCount
	}
	sm.Shards = sm.Shards[:len(sm.Shards)-count]
	sm.rebalanceNodes()
}

func (sm *ShardManager) rebalanceNodes() {
	allNodes := sm.network.GetAllNodes()
	nodesPerShard := len(allNodes) / len(sm.Shards)

	for i, node := range allNodes {
		shardIndex := i / nodesPerShard
		if shardIndex >= len(sm.Shards) {
			shardIndex = len(sm.Shards) - 1
		}
		sm.Shards[shardIndex].AssignNode(node)
	}

	for _, shard := range sm.Shards {
		shard.RedistributeData()
	}
}

// Add this method to ShardManager
func (sm *ShardManager) getShardForBlock(block *Block) int {
	// Implement logic to determine which shard a block belongs to
	// This could be based on the block's hash, transactions, or other criteria
	return int(block.Hash[0]) % len(sm.Shards) // Simple example using the first byte of the block hash
}
