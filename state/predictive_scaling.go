// predictive_scaling.go
package state

import (
	"log"
	"math"
	"sync"
	"time"
)

type PredictiveScaling struct {
	HistoricalLoad   map[int][]float64
	PredictionWindow time.Duration
	ScalingThreshold float64
	mu               sync.RWMutex
}

func NewPredictiveScaling() *PredictiveScaling {
	return &PredictiveScaling{
		HistoricalLoad:   make(map[int][]float64),
		PredictionWindow: time.Minute * 10,
		ScalingThreshold: 0.7,
	}
}

func (ps *PredictiveScaling) StartMonitoring(sm *StateManager) {
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond) // Faster for testing
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ps.predictAndScale(sm)
			case <-sm.stopChan:
				return
			}
		}
	}()
}

func (ps *PredictiveScaling) predictAndScale(sm *StateManager) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	for shardID, metrics := range sm.metrics.shardMetrics {
		currentLoad := metrics.LoadFactor
		history := ps.HistoricalLoad[shardID]

		history = append(history, currentLoad)
		if len(history) > 60 {
			history = history[1:]
		}
		ps.HistoricalLoad[shardID] = history

		if prediction := ps.CalculateTrend(history); prediction > ps.ScalingThreshold {
			ps.allocateAdditionalResources(sm, shardID)
		}
	}
}

func (ps *PredictiveScaling) CalculateTrend(history []float64) float64 {
	if len(history) < 2 {
		return history[0]
	}

	// Weighted moving average with linear regression
	recentLoad := history[len(history)-1]
	slope := (history[len(history)-1] - history[0]) / float64(len(history)-1)
	prediction := recentLoad + (slope * 5) // Project 5 intervals ahead

	// Apply bounds
	return math.Max(0.5, math.Min(1.5, prediction))
}

func (ps *PredictiveScaling) allocateAdditionalResources(sm *StateManager, shardID int) {
	partition := sm.partitions[shardID]
	partition.mu.Lock()
	defer partition.mu.Unlock()

	log.Printf("Allocating additional resources to shard %d based on prediction", shardID)
}
