package state

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/thrylos-labs/thrylos/types"
)

func (sm *StateManagerImpl) StopStateSyncLoop() {
	sm.CloseStopChan()
}

// NewStateManager creates a new state sharding manager
func NewStateManager(networkHandler types.NetworkInterface, numShards int) *StateManagerImpl {
	if numShards < 1 {
		numShards = 1
	}

	metrics := NewStateMetrics(numShards)

	// Create a new StateManager
	stateManager := &types.StateManager{}

	sm := &StateManagerImpl{
		StateManager: stateManager,
	}

	// Initialize partitions
	partitions := make([]*types.StatePartition, numShards)
	for i := 0; i < numShards; i++ {
		partitions[i] = &types.StatePartition{
			ID:           i,
			StartAddress: calculatePartitionStart(i, numShards),
			EndAddress:   calculatePartitionEnd(i, numShards),
			Balances:     make(map[string]int64),
			UTXOs:        make(map[string]*types.UTXO),
			LastUpdated:  time.Now().Unix(),
		}
	}

	// Use accessor methods to initialize the StateManager
	sm.SetPartitions(partitions)
	sm.SetNetwork(networkHandler)
	sm.SetTotalShards(numShards)
	sm.InitStopChan()
	sm.SetMetrics(metrics.StateMetrics) // Access the embedded StateMetrics

	// Create and set consensus
	consensus := NewAdaptiveConsensus(metrics.StateMetrics) // Pass the embedded StateMetrics
	sm.SetConsensus(consensus.AdaptiveConsensus)            // Access the embedded AdaptiveConsensus

	// Create and set scaling
	scaling := NewShardScaling()
	sm.SetScaling(scaling.ShardScaling) // Access the embedded ShardScaling

	// Start monitoring
	scaling.MonitorShards(sm.StateManager)

	sm.StartRelocationMonitor()
	consensus.Start() // Start consensus monitoring

	return sm
}

// GetShardAccessCount gets access count for a shard
func (sm *StateManagerImpl) GetShardAccessCount(shardID int) int64 {
	metrics := sm.GetMetrics()
	if metrics == nil {
		return 0
	}

	metrics.Mu.RLock()
	defer metrics.Mu.RUnlock()

	if shardMetric, exists := metrics.ShardMetrics[shardID]; exists {
		shardMetric.Mu.RLock()
		defer shardMetric.Mu.RUnlock()
		return shardMetric.AccessCount
	}
	return 0
}

func (sm *StateManagerImpl) GetShardModifyCount(shardID int) int64 {
	metrics := sm.GetMetrics()
	if metrics == nil {
		return 0
	}

	metrics.Mu.RLock()
	defer metrics.Mu.RUnlock()

	if shardMetric, exists := metrics.ShardMetrics[shardID]; exists {
		shardMetric.Mu.RLock()
		defer shardMetric.Mu.RUnlock()
		return shardMetric.ModifyCount
	}
	return 0
}

func (sm *StateManagerImpl) GetShardLoadFactor(shardID int) float64 {
	metrics := sm.GetMetrics()
	if metrics == nil {
		return 0.0
	}

	metrics.Mu.RLock()
	defer metrics.Mu.RUnlock()

	if shardMetric, exists := metrics.ShardMetrics[shardID]; exists {
		shardMetric.Mu.RLock()
		defer shardMetric.Mu.RUnlock()
		return shardMetric.LoadFactor
	}
	return 0.0
}

// GetResponsiblePartition determines which partition handles a given address
func (sm *StateManagerImpl) GetResponsiblePartition(address string) *types.StatePartition {
	partitions := sm.GetPartitions()
	for _, partition := range partitions {
		if isAddressInPartition(address, partition.StartAddress, partition.EndAddress) {
			return partition
		}
	}
	return nil
}

// UpdateState updates state data in the appropriate partition
func (sm *StateManagerImpl) UpdateState(address string, balance int64, utxo *types.UTXO) error {
	partition := sm.GetResponsiblePartition(address)
	if partition == nil {
		return fmt.Errorf("no responsible partition found for address: %s", address)
	}

	partition.Lock()
	defer partition.Unlock()

	partition.Balances[address] = balance
	if utxo != nil {
		partition.UTXOs[utxo.TransactionID] = utxo
	}
	partition.LastUpdated = time.Now().Unix()

	// Record metrics
	metrics := sm.GetMetrics()
	metrics.Mu.Lock()
	if shardMetric, exists := metrics.ShardMetrics[partition.ID]; exists {
		shardMetric.RecordModify()
		shardMetric.UpdateLoadFactor(len(partition.Balances))
	}
	metrics.Mu.Unlock()

	log.Printf("Updated state for address %s in partition %d", address, partition.ID)
	return nil
}

func (sm *StateManagerImpl) handleStateSync(message types.NetworkMessage) error {
	data, ok := message.Data.([]byte)
	if !ok {
		return fmt.Errorf("invalid data type in message")
	}

	var partition types.StatePartition
	if err := json.Unmarshal(data, &partition); err != nil {
		return fmt.Errorf("failed to unmarshal partition state: %v", err)
	}

	// Use the Lock/Unlock methods from the embedded StateManager
	sm.StateManager.Lock()
	defer sm.StateManager.Unlock()

	partitions := sm.GetPartitions()
	for i, p := range partitions {
		if p.ID == partition.ID {
			// Now you can use the update method
			sm.UpdatePartition(i, &partition)
			break
		}
	}
	return nil
}

// Add periodic state synchronization
func (sm *StateManagerImpl) StartStateSyncLoop() {
	go func() {
		ticker := time.NewTicker(1 * time.Second) // Shorter interval for testing
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				partitions := sm.GetPartitions()
				for _, partition := range partitions {
					if err := sm.SyncPartitionState(partition); err != nil {
						log.Printf("Failed to sync partition %d: %v", partition.ID, err)
					}
				}
			case <-sm.GetStopChan():
				return
			}
		}
	}()
}

// GetBalance retrieves balance from the appropriate partition
func (sm *StateManagerImpl) GetBalance(address string) (int64, error) {
	partition := sm.GetResponsiblePartition(address)
	if partition == nil {
		return 0, fmt.Errorf("no responsible partition found for address: %s", address)
	}

	partition.RLock()
	defer partition.RUnlock()

	balance, exists := partition.Balances[address]
	if !exists {
		return 0, fmt.Errorf("address not found: %s", address)
	}

	// Record metrics
	metrics := sm.GetMetrics()
	if metrics != nil && metrics.ShardMetrics != nil {
		if shardMetric, exists := metrics.ShardMetrics[partition.ID]; exists {
			shardMetric.RecordAccess()
		}
	}

	return balance, nil
}

// GetUTXOs retrieves UTXOs from the appropriate partition
func (sm *StateManagerImpl) GetUTXOs(address string) ([]*types.UTXO, error) {
	partition := sm.GetResponsiblePartition(address)
	if partition == nil {
		return nil, fmt.Errorf("no responsible partition found for address: %s", address)
	}

	partition.RLock()
	defer partition.RUnlock()

	var utxos []*types.UTXO
	for _, utxo := range partition.UTXOs {
		if utxo.OwnerAddress == address {
			utxos = append(utxos, utxo)
		}
	}

	return utxos, nil
}

// Helper functions
func calculatePartitionStart(partitionID, totalPartitions int) string {
	if partitionID == 0 {
		return "tl1"
	}
	return fmt.Sprintf("tl1%02d", partitionID) // Add zero padding
}

func calculatePartitionEnd(partitionID, totalPartitions int) string {
	if partitionID == totalPartitions-1 {
		return "tl1zzzzzzzzzzzz"
	}
	return fmt.Sprintf("tl1%02d", partitionID+1) // Add zero padding
}

func isAddressInPartition(address, start, end string) bool {
	// Ensure address starts with tl1
	if !strings.HasPrefix(address, "tl1") {
		return false
	}
	return address >= start && address <= end
}

// Add these methods to your StateManagerImpl struct in the state package

// SimulateHighLoad simulates high load on a shard (for testing)
func (sm *StateManagerImpl) SimulateHighLoad(shardID int, count int) error {
	metrics := sm.GetMetrics()
	if metrics == nil || metrics.ShardMetrics == nil {
		return fmt.Errorf("metrics not initialized")
	}

	metrics.Mu.Lock()
	shardMetrics, exists := metrics.ShardMetrics[shardID]
	if !exists {
		metrics.Mu.Unlock()
		return fmt.Errorf("shard ID %d not found", shardID)
	}
	metrics.Mu.Unlock()

	for i := 0; i < count; i++ {
		shardMetrics.RecordAccess()
		shardMetrics.RecordModify()
	}
	shardMetrics.UpdateLoadFactor(900)

	return nil
}

// CheckAndRelocateForTesting exposes the checkAndRelocate method for testing
func (sm *StateManagerImpl) CheckAndRelocateForTesting() error {
	sm.checkAndRelocate()
	return nil
}

// RecordMetricsForTesting records metrics for a shard (for testing)
func (sm *StateManagerImpl) RecordMetricsForTesting(shardID int) error {
	metrics := sm.GetMetrics()
	if metrics == nil || metrics.ShardMetrics == nil {
		return fmt.Errorf("metrics not initialized")
	}

	metrics.Mu.Lock()
	shardMetrics, exists := metrics.ShardMetrics[shardID]
	if !exists {
		metrics.Mu.Unlock()
		return fmt.Errorf("shard ID %d not found", shardID)
	}
	metrics.Mu.Unlock()

	shardMetrics.RecordAccess()
	shardMetrics.RecordModify()

	return nil
}

// ResetMetricsForTesting resets metrics for a shard (for testing)
func (sm *StateManagerImpl) ResetMetricsForTesting(shardID int) error {
	metrics := sm.GetMetrics()
	if metrics == nil || metrics.ShardMetrics == nil {
		return fmt.Errorf("metrics not initialized")
	}

	metrics.Mu.Lock()
	shardMetrics, exists := metrics.ShardMetrics[shardID]
	if !exists {
		metrics.Mu.Unlock()
		return fmt.Errorf("shard ID %d not found", shardID)
	}
	metrics.Mu.Unlock()

	shardMetrics.Mu.Lock()
	shardMetrics.AccessCount = 0
	shardMetrics.ModifyCount = 0
	shardMetrics.Mu.Unlock()

	return nil
}
