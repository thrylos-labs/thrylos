package state

import (
	"time"

	"github.com/thrylos-labs/thrylos/shared"
)

type StateMetricsImpl struct {
	*shared.StateMetrics
}

type ShardMetricsImpl struct {
	*shared.ShardMetrics
}

func NewStateMetrics(numShards int) *StateMetricsImpl {
	metrics := &shared.StateMetrics{
		ShardMetrics: make(map[int]*shared.ShardMetrics),
	}

	for i := 0; i < numShards; i++ {
		metrics.ShardMetrics[i] = &shared.ShardMetrics{
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
