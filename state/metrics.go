package state

import (
	"time"

	"github.com/thrylos-labs/thrylos/types"
)

type StateMetricsImpl struct {
	*types.StateMetrics
}

type ShardMetricsImpl struct {
	*types.ShardMetrics
}

func NewStateMetrics(numShards int) *StateMetricsImpl {
	metrics := &types.StateMetrics{
		ShardMetrics: make(map[int]*types.ShardMetrics),
	}

	for i := 0; i < numShards; i++ {
		metrics.ShardMetrics[i] = &types.ShardMetrics{
			LastUpdated: time.Now(),
		}
	}

	return &StateMetricsImpl{
		StateMetrics: metrics,
	}
}

func (sm *ShardMetricsImpl) RecordAccess() {
	sm.Mu.Lock()
	defer sm.Mu.Unlock()
	sm.AccessCount++
	sm.LastUpdated = time.Now()
}

func (sm *ShardMetricsImpl) RecordModify() {
	sm.Mu.Lock()
	defer sm.Mu.Unlock()
	sm.ModifyCount++
	sm.LastUpdated = time.Now()
}

func (sm *ShardMetricsImpl) UpdateLoadFactor(stateSize int) {
	sm.Mu.Lock()
	defer sm.Mu.Unlock()
	sm.LoadFactor = float64(stateSize) / 1000.0
}
