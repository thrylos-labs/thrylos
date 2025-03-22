package state

import (
	"log"
	"time"

	"github.com/thrylos-labs/thrylos/types"
)

type ShardScalingImpl struct {
	*types.ShardScaling
}

// NewShardScaling creates a new shard scaling manager
func NewShardScaling() *ShardScalingImpl {
	scaling := &ShardScalingImpl{
		ShardScaling: &types.ShardScaling{
			LoadThresholds: struct {
				Split float64
				Merge float64
			}{
				Split: 1.20, // Increase from 0.80 to 1.20
				Merge: 0.40, // Increase from 0.20 to 0.40
			},
			Limits: struct {
				MinShards int
				MaxShards int
			}{
				MinShards: 1,
				MaxShards: 32,
			},
			CooldownPeriod: 5 * time.Minute,
		},
	}
	return scaling
}

// MonitorShards starts a goroutine to periodically evaluate shard scaling needs
func (s *ShardScalingImpl) MonitorShards(sm *types.StateManager) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.evaluateShards(sm)
			case <-sm.GetStopChan():
				return
			}
		}
	}()
}

// evaluateShards analyzes shard metrics to determine if scaling is needed
func (s *ShardScalingImpl) evaluateShards(sm *types.StateManager) {
	// Lock ShardScaling for the duration of evaluation
	s.Lock()
	defer s.Unlock()

	// Check cooldown period
	if time.Since(s.GetLastScaleTime()) < s.GetCooldownPeriod() {
		return
	}

	// Get partitions using the accessor methods
	partitions := sm.GetPartitions()

	for _, partition := range partitions {
		loadFactor := sm.GetShardLoadFactor(partition.ID)

		// Consider splitting
		if loadFactor > s.LoadThresholds.Split && len(partitions) < s.Limits.MaxShards {
			log.Printf("High load detected on shard %d (%.2f). Initiating split.",
				partition.ID, loadFactor)
			// Implement split logic
			s.SetLastScaleTime(time.Now())
		}

		// Consider merging
		if loadFactor < s.LoadThresholds.Merge && len(partitions) > s.Limits.MinShards {
			log.Printf("Low load detected on shard %d (%.2f). Evaluating merge possibility.",
				partition.ID, loadFactor)
			// Implement merge logic
			s.SetLastScaleTime(time.Now())
		}
	}
}
