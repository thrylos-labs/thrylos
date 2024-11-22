package state

import (
	"sync"
	"time"
)

type ShardMetrics struct {
	AccessCount int64
	ModifyCount int64
	LoadFactor  float64
	Latency     time.Duration
	LastUpdated time.Time
	mu          sync.RWMutex
}

type StateMetrics struct {
	shardMetrics map[int]*ShardMetrics
	mu           sync.RWMutex
}

func NewStateMetrics(numShards int) *StateMetrics {
	metrics := &StateMetrics{
		shardMetrics: make(map[int]*ShardMetrics),
	}

	for i := 0; i < numShards; i++ {
		metrics.shardMetrics[i] = &ShardMetrics{
			LastUpdated: time.Now(),
		}
	}

	return metrics
}

func (sm *ShardMetrics) RecordAccess() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.AccessCount++
	sm.LastUpdated = time.Now()
}

func (sm *ShardMetrics) RecordModify() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.ModifyCount++
	sm.LastUpdated = time.Now()
}

func (sm *ShardMetrics) UpdateLoadFactor(stateSize int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.LoadFactor = float64(stateSize) / 1000.0 // Example threshold
}
