package state

import (
	"github.com/thrylos-labs/thrylos/shared"
)

type StateManagerImpl struct {
	*shared.StateManager
}

// func (sm *StateManagerImpl) StopStateSyncLoop() {
// 	close(sm.stopChan)
// }

// // NewStateManager creates a new state sharding manager
// func NewStateManager(networkHandler shared.NetworkInterface, numShards int) *StateManagerImpl {
// 	if numShards < 1 {
// 		numShards = 1
// 	}

// 	metrics := NewStateMetrics(numShards)
// 	sm := &StateManagerImpl{
// 		partitions:  make([]*StatePartition, numShards),
// 		network:     networkHandler,
// 		totalShards: numShards,
// 		stopChan:    make(chan struct{}),
// 		metrics:     metrics, // Use the already created metrics
// 		consensus:   NewAdaptiveConsensus(metrics),
// 		Scaling:     NewShardScaling(), // Initialize with capital S
// 	}

// 	// Rest of initialization remains the same
// 	for i := 0; i < numShards; i++ {
// 		sm.partitions[i] = &StatePartition{
// 			ID:           i,
// 			StartAddress: calculatePartitionStart(i, numShards),
// 			EndAddress:   calculatePartitionEnd(i, numShards),
// 			Balances:     make(map[string]int64),
// 			UTXOs:        make(map[string]*shared.UTXO),
// 			LastUpdated:  time.Now().Unix(),
// 		}
// 	}

// 	sm.Scaling.MonitorShards(sm) // Use capital S here too

// 	sm.StartRelocationMonitor()
// 	sm.consensus.Start() // Start consensus monitoring

// 	return sm
// }

// // Add these methods to your StateManager struct
// func (sm *StateManagerImpl) GetShardAccessCount(shardID int) int64 {
// 	sm.mu.RLock()
// 	defer sm.mu.RUnlock()

// 	if metrics, exists := sm.metrics.shardMetrics[shardID]; exists {
// 		return metrics.AccessCount
// 	}
// 	return 0
// }

// func (sm *StateManagerImpl) GetShardModifyCount(shardID int) int64 {
// 	sm.mu.RLock()
// 	defer sm.mu.RUnlock()

// 	if metrics, exists := sm.metrics.shardMetrics[shardID]; exists {
// 		return metrics.ModifyCount
// 	}
// 	return 0
// }

// func (sm *StateManagerImpl) GetShardLoadFactor(shardID int) float64 {
// 	sm.mu.RLock()
// 	defer sm.mu.RUnlock()

// 	if metrics, exists := sm.metrics.shardMetrics[shardID]; exists {
// 		return metrics.LoadFactor
// 	}
// 	return 0.0
// }

// // GetResponsiblePartition determines which partition handles a given address
// func (sm *StateManagerImpl) GetResponsiblePartition(address string) *shared.StatePartition {
// 	sm.mu.RLock()
// 	defer sm.mu.RUnlock()

// 	for _, partition := range sm.partitions {
// 		if isAddressInPartition(address, partition.StartAddress, partition.EndAddress) {
// 			return partition
// 		}
// 	}
// 	return nil
// }

// // UpdateState updates state data in the appropriate partition
// func (sm *StateManagerImpl) UpdateState(address string, balance int64, utxo *shared.UTXO) error {
// 	partition := sm.GetResponsiblePartition(address)
// 	if partition == nil {
// 		return fmt.Errorf("no responsible partition found for address: %s", address)
// 	}

// 	partition.mu.Lock()
// 	defer partition.mu.Unlock()

// 	partition.Balances[address] = balance
// 	if utxo != nil {
// 		partition.UTXOs[utxo.TransactionID] = utxo
// 	}
// 	partition.LastUpdated = time.Now().Unix()

// 	// Record metrics
// 	sm.metrics.shardMetrics[partition.ID].RecordModify()
// 	sm.metrics.shardMetrics[partition.ID].UpdateLoadFactor(len(partition.Balances))

// 	log.Printf("Updated state for address %s in partition %d", address, partition.ID)
// 	return nil
// }

// func (sm *StateManagerImpl) syncPartitionState(partition *shared.StatePartition) error {
// 	partitionData, err := json.Marshal(partition)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal partition: %v", err)
// 	}

// 	message := shared.NetworkMessage{
// 		Type:      "STATE_SYNC",
// 		Data:      partitionData,
// 		Timestamp: time.Now(),
// 	}

// 	messageBytes, err := json.Marshal(message)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal state sync message: %v", err)
// 	}

// 	return sm.network.BroadcastMessage(messageBytes)
// }

// func (sm *StateManagerImpl) handleStateSync(message shared.NetworkMessage) error {
// 	data, ok := message.Data.([]byte)
// 	if !ok {
// 		return fmt.Errorf("invalid data type in message")
// 	}

// 	var partition shared.StatePartition
// 	if err := json.Unmarshal(data, &partition); err != nil {
// 		return fmt.Errorf("failed to unmarshal partition state: %v", err)
// 	}

// 	sm.mu.Lock()
// 	defer sm.mu.Unlock()

// 	for i, p := range sm.partitions {
// 		if p.ID == partition.ID {
// 			sm.partitions[i] = &partition
// 			break
// 		}
// 	}
// 	return nil
// }

// // Add periodic state synchronization
// func (sm *StateManagerImpl) StartStateSyncLoop() {
// 	go func() {
// 		ticker := time.NewTicker(1 * time.Second) // Shorter interval for testing
// 		defer ticker.Stop()

// 		for {
// 			select {
// 			case <-ticker.C:
// 				for _, partition := range sm.partitions {
// 					if err := sm.syncPartitionState(partition); err != nil {
// 						log.Printf("Failed to sync partition %d: %v", partition.ID, err)
// 					}
// 				}
// 			case <-sm.stopChan:
// 				return
// 			}
// 		}
// 	}()
// }

// // GetBalance retrieves balance from the appropriate partition
// func (sm *StateManagerImpl) GetBalance(address string) (int64, error) {
// 	partition := sm.GetResponsiblePartition(address)
// 	if partition == nil {
// 		return 0, fmt.Errorf("no responsible partition found for address: %s", address)
// 	}

// 	partition.mu.RLock()
// 	defer partition.mu.RUnlock()

// 	balance, exists := partition.Balances[address]
// 	if !exists {
// 		return 0, fmt.Errorf("address not found: %s", address)
// 	}

// 	// Record metrics
// 	sm.metrics.shardMetrics[partition.ID].RecordAccess()

// 	return balance, nil
// }

// // GetUTXOs retrieves UTXOs from the appropriate partition
// func (sm *StateManagerImpl) GetUTXOs(address string) ([]*shared.UTXO, error) {
// 	partition := sm.GetResponsiblePartition(address)
// 	if partition == nil {
// 		return nil, fmt.Errorf("no responsible partition found for address: %s", address)
// 	}

// 	partition.mu.RLock()
// 	defer partition.mu.RUnlock()

// 	var utxos []*shared.UTXO
// 	for _, utxo := range partition.UTXOs {
// 		if utxo.OwnerAddress == address {
// 			utxos = append(utxos, utxo)
// 		}
// 	}

// 	return utxos, nil
// }

// // Helper functions
// func calculatePartitionStart(partitionID, totalPartitions int) string {
// 	if partitionID == 0 {
// 		return "tl1"
// 	}
// 	return fmt.Sprintf("tl1%02d", partitionID) // Add zero padding
// }

// func calculatePartitionEnd(partitionID, totalPartitions int) string {
// 	if partitionID == totalPartitions-1 {
// 		return "tl1zzzzzzzzzzzz"
// 	}
// 	return fmt.Sprintf("tl1%02d", partitionID+1) // Add zero padding
// }

// func isAddressInPartition(address, start, end string) bool {
// 	// Ensure address starts with tl1
// 	if !strings.HasPrefix(address, "tl1") {
// 		return false
// 	}
// 	return address >= start && address <= end
// }
