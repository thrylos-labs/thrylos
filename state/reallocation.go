package state

// type StateManagerImpl struct {
// 	*types.StateManager
// }

// func (sm *StateManagerImpl) StartRelocationMonitor() {
// 	go func() {
// 		ticker := time.NewTicker(5 * time.Minute)
// 		defer ticker.Stop()

// 		for {
// 			select {
// 			case <-ticker.C:
// 				sm.checkAndRelocate()
// 			case <-sm.stopChan:
// 				return
// 			}
// 		}
// 	}()
// }

// func (sm *StateManagerImpl) checkAndRelocate() {
// 	candidates := sm.findRelocationCandidates()

// 	for _, candidate := range candidates {
// 		if err := sm.relocateState(candidate); err != nil {
// 			log.Printf("Failed to relocate state for %s: %v", candidate.Address, err)
// 			continue
// 		}
// 	}
// }

// func (sm *StateManagerImpl) findRelocationCandidates() []types.RelocationCandidate {
// 	var candidates []types.RelocationCandidate

// 	// Find overloaded shards
// 	overloadedShards := sm.findOverloadedShards()
// 	underutilizedShards := sm.findUnderutilizedShards()

// 	for _, fromShard := range overloadedShards {
// 		for _, address := range sm.getHighAccessAddresses(fromShard) {
// 			if toShard := sm.findOptimalShard(address, underutilizedShards); toShard != -1 {
// 				candidates = append(candidates, types.RelocationCandidate{
// 					Address:   address,
// 					FromShard: fromShard,
// 					ToShard:   toShard,
// 				})
// 			}
// 		}
// 	}

// 	return candidates
// }

// func (sm *StateManagerImpl) relocateState(candidate types.RelocationCandidate) error {
// 	sm.mu.Lock()
// 	defer sm.mu.Unlock()

// 	// Get state data
// 	fromPartition := sm.partitions[candidate.FromShard]
// 	toPartition := sm.partitions[candidate.ToShard]

// 	// Move balance
// 	balance := fromPartition.Balances[candidate.Address]
// 	toPartition.Balances[candidate.Address] = balance
// 	delete(fromPartition.Balances, candidate.Address)

// 	// Move UTXOs
// 	for txID, utxo := range fromPartition.UTXOs {
// 		if utxo.OwnerAddress == candidate.Address {
// 			toPartition.UTXOs[txID] = utxo
// 			delete(fromPartition.UTXOs, txID)
// 		}
// 	}

// 	// Update metrics
// 	sm.metrics.shardMetrics[candidate.ToShard].RecordModify()

// 	// Broadcast state change
// 	return sm.syncPartitionState(toPartition)
// }

// func (sm *StateManagerImpl) getHighAccessAddresses(shardID int) []string {
// 	threshold := int64(100) // High access threshold
// 	var addresses []string
// 	metrics := sm.metrics.shardMetrics[shardID]
// 	partition := sm.partitions[shardID]

// 	partition.mu.RLock()
// 	defer partition.mu.RUnlock()

// 	for address := range partition.Balances {
// 		if metrics.AccessCount > threshold {
// 			addresses = append(addresses, address)
// 		}
// 	}

// 	return addresses
// }

// func (sm *StateManagerImpl) findOptimalShard(address string, candidates []int) int {
// 	if len(candidates) == 0 {
// 		return -1
// 	}

// 	type shardScore struct {
// 		id    int
// 		score float64
// 	}

// 	var scores []shardScore

// 	for _, id := range candidates {
// 		metrics := sm.metrics.shardMetrics[id]
// 		score := 1.0 - metrics.LoadFactor // Lower load is better
// 		scores = append(scores, shardScore{id, score})
// 	}

// 	// Sort by score descending
// 	sort.Slice(scores, func(i, j int) bool {
// 		return scores[i].score > scores[j].score
// 	})

// 	return scores[0].id
// }

// func (sm *StateManagerImpl) findOverloadedShards() []int {
// 	threshold := 0.8 // 80% load factor
// 	var overloaded []int

// 	for id, metrics := range sm.metrics.shardMetrics {
// 		if metrics.LoadFactor > threshold {
// 			overloaded = append(overloaded, id)
// 		}
// 	}

// 	return overloaded
// }

// func (sm *StateManagerImpl) findUnderutilizedShards() []int {
// 	threshold := 0.3 // 30% load factor
// 	var underutilized []int

// 	for id, metrics := range sm.metrics.shardMetrics {
// 		if metrics.LoadFactor < threshold {
// 			underutilized = append(underutilized, id)
// 		}
// 	}

// 	return underutilized
// }
