package state

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/thrylos-labs/thrylos/types"
)

type StateManagerImpl struct {
	*types.StateManager
}

func (sm *StateManagerImpl) StartRelocationMonitor() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sm.checkAndRelocate()
			case <-sm.GetStopChan(): // Use accessor method
				return
			}
		}
	}()
}

func (sm *StateManagerImpl) checkAndRelocate() {
	candidates := sm.findRelocationCandidates()

	for _, candidate := range candidates {
		if err := sm.relocateState(candidate); err != nil {
			log.Printf("Failed to relocate state for %s: %v", candidate.Address, err)
			continue
		}
	}
}

func (sm *StateManagerImpl) findRelocationCandidates() []types.RelocationCandidate {
	var candidates []types.RelocationCandidate

	// Find overloaded shards
	overloadedShards := sm.findOverloadedShards()
	underutilizedShards := sm.findUnderutilizedShards()

	for _, fromShard := range overloadedShards {
		for _, address := range sm.getHighAccessAddresses(fromShard) {
			if toShard := sm.findOptimalShard(address, underutilizedShards); toShard != -1 {
				candidates = append(candidates, types.RelocationCandidate{
					Address:   address,
					FromShard: fromShard,
					ToShard:   toShard,
				})
			}
		}
	}

	return candidates
}

func (sm *StateManagerImpl) relocateState(candidate types.RelocationCandidate) error {
	mutex := sm.GetMutex()
	mutex.Lock()
	defer mutex.Unlock()

	// Get state data
	fromPartition := sm.GetPartition(candidate.FromShard)
	toPartition := sm.GetPartition(candidate.ToShard)

	// Move balance
	balance := fromPartition.Balances[candidate.Address]
	toPartition.Balances[candidate.Address] = balance
	delete(fromPartition.Balances, candidate.Address)

	// Move UTXOs
	for txID, utxo := range fromPartition.UTXOs {
		if utxo.OwnerAddress == candidate.Address {
			toPartition.UTXOs[txID] = utxo
			delete(fromPartition.UTXOs, txID)
		}
	}

	// Update metrics
	metrics := sm.GetMetrics()
	shardMetric := metrics.ShardMetrics[candidate.ToShard]
	shardMetric.RecordModify()

	// Broadcast state change
	return sm.SyncPartitionState(toPartition)
}

func (sm *StateManagerImpl) getHighAccessAddresses(shardID int) []string {
	threshold := int64(100) // High access threshold
	var addresses []string

	metrics := sm.GetMetrics()
	shardMetric := metrics.ShardMetrics[shardID]
	partition := sm.GetPartition(shardID)

	// Check if access count exceeds threshold
	shardMetric.Mu.RLock()
	exceedsThreshold := shardMetric.AccessCount > threshold
	shardMetric.Mu.RUnlock()

	// If it doesn't exceed threshold, return empty list
	if !exceedsThreshold {
		return addresses
	}

	// Use accessor methods instead of direct mutex access
	partition.RLock()
	defer partition.RUnlock()

	for address := range partition.Balances {
		addresses = append(addresses, address)
	}

	return addresses
}

func (sm *StateManagerImpl) findOptimalShard(address string, candidates []int) int {
	if len(candidates) == 0 {
		return -1
	}

	type shardScore struct {
		id    int
		score float64
	}

	var scores []shardScore
	metrics := sm.GetMetrics()

	for _, id := range candidates {
		shardMetric := metrics.ShardMetrics[id]
		score := 1.0 - shardMetric.LoadFactor // Lower load is better
		scores = append(scores, shardScore{id, score})
	}

	// Sort by score descending
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})

	return scores[0].id
}

func (sm *StateManagerImpl) findOverloadedShards() []int {
	threshold := 0.8 // 80% load factor
	var overloaded []int

	metrics := sm.GetMetrics()

	for id, shardMetric := range metrics.ShardMetrics {
		if shardMetric.LoadFactor > threshold {
			overloaded = append(overloaded, id)
		}
	}

	return overloaded
}

func (sm *StateManagerImpl) findUnderutilizedShards() []int {
	threshold := 0.3 // 30% load factor
	var underutilized []int

	metrics := sm.GetMetrics()

	for id, shardMetric := range metrics.ShardMetrics {
		if shardMetric.LoadFactor < threshold {
			underutilized = append(underutilized, id)
		}
	}

	return underutilized
}

// Add this method to make the code compile
func (sm *StateManagerImpl) SyncPartitionState(partition *types.StatePartition) error {
	partitionData, err := json.Marshal(partition)
	if err != nil {
		return fmt.Errorf("failed to marshal partition: %v", err)
	}

	message := types.NetworkMessage{
		Type:      "STATE_SYNC",
		Data:      partitionData,
		Timestamp: time.Now(),
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal state sync message: %v", err)
	}

	network := sm.GetNetwork()
	return network.BroadcastMessage(messageBytes)
}
