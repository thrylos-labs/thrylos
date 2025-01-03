// predictive_scaling.go
package state

import (
	"log"
	"sync"
	"time"
)

type PredictiveScaling struct {
	historicalLoad   map[int][]float64
	predictionWindow time.Duration
	scalingThreshold float64
	mu               sync.RWMutex
}

func NewPredictiveScaling() *PredictiveScaling {
	return &PredictiveScaling{
		historicalLoad:   make(map[int][]float64),
		predictionWindow: time.Minute * 10,
		scalingThreshold: 0.7,
	}
}

func (ps *PredictiveScaling) StartMonitoring(sm *StateManager) {
	go func() {
		ticker := time.NewTicker(time.Minute)
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
		history := ps.historicalLoad[shardID]

		history = append(history, currentLoad)
		if len(history) > 60 {
			history = history[1:]
		}
		ps.historicalLoad[shardID] = history

		if prediction := ps.calculateTrend(history); prediction > ps.scalingThreshold {
			ps.allocateAdditionalResources(sm, shardID)
		}
	}
}

func (ps *PredictiveScaling) calculateTrend(history []float64) float64 {
	if len(history) < 2 {
		return 0
	}

	sum := 0.0
	for _, v := range history[len(history)/2:] {
		sum += v
	}
	return sum / float64(len(history)/2)
}

func (ps *PredictiveScaling) allocateAdditionalResources(sm *StateManager, shardID int) {
	partition := sm.partitions[shardID]
	partition.mu.Lock()
	defer partition.mu.Unlock()

	log.Printf("Allocating additional resources to shard %d based on prediction", shardID)
}
