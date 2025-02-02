package state

// type ShardScaling struct {
// 	LoadThresholds struct {
// 		Split float64 // When to split a shard
// 		Merge float64 // When to consider merging shards
// 	}
// 	Limits struct {
// 		MinShards int
// 		MaxShards int
// 	}
// 	cooldownPeriod time.Duration
// 	lastScaleTime  time.Time
// 	mu             sync.RWMutex
// }

// func NewShardScaling() *ShardScaling {
// 	return &ShardScaling{
// 		LoadThresholds: struct {
// 			Split float64
// 			Merge float64
// 		}{
// 			Split: 1.20, // Increase from 0.80 to 1.20
// 			Merge: 0.40, // Increase from 0.20 to 0.40
// 		},
// 		Limits: struct {
// 			MinShards int
// 			MaxShards int
// 		}{
// 			MinShards: 1,
// 			MaxShards: 32,
// 		},
// 		cooldownPeriod: 5 * time.Minute,
// 	}
// }

// func (s *ShardScaling) MonitorShards(sm *StateManager) {
// 	go func() {
// 		ticker := time.NewTicker(30 * time.Second)
// 		defer ticker.Stop()

// 		for {
// 			select {
// 			case <-ticker.C:
// 				s.evaluateShards(sm)
// 			case <-sm.stopChan:
// 				return
// 			}
// 		}
// 	}()
// }

// func (s *ShardScaling) evaluateShards(sm *StateManager) {
// 	s.mu.Lock()
// 	defer s.mu.Unlock()

// 	// Check cooldown period
// 	if time.Since(s.lastScaleTime) < s.cooldownPeriod {
// 		return
// 	}

// 	sm.mu.RLock()
// 	defer sm.mu.RUnlock()

// 	for _, partition := range sm.partitions {
// 		loadFactor := sm.GetShardLoadFactor(partition.ID)

// 		// Consider splitting
// 		if loadFactor > s.LoadThresholds.Split && len(sm.partitions) < s.Limits.MaxShards {
// 			log.Printf("High load detected on shard %d (%.2f). Initiating split.",
// 				partition.ID, loadFactor)
// 			// Implement split logic
// 			s.lastScaleTime = time.Now()
// 		}

// 		// Consider merging
// 		if loadFactor < s.LoadThresholds.Merge && len(sm.partitions) > s.Limits.MinShards {
// 			log.Printf("Low load detected on shard %d (%.2f). Evaluating merge possibility.",
// 				partition.ID, loadFactor)
// 			// Implement merge logic
// 			s.lastScaleTime = time.Now()
// 		}
// 	}
// }
