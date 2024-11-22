package state

import (
	"sync"
	"time"
)

type ConsensusParams struct {
	BlockSize        int
	ConfirmationTime time.Duration
	MinValidators    int
	Threshold        float64
}

type AdaptiveConsensus struct {
	params         map[int]*ConsensusParams
	metrics        *StateMetrics
	updateInterval time.Duration
	mu             sync.RWMutex
	stopChan       chan struct{}
}

func NewAdaptiveConsensus(metrics *StateMetrics) *AdaptiveConsensus {
	ac := &AdaptiveConsensus{
		params:         make(map[int]*ConsensusParams),
		metrics:        metrics,
		updateInterval: time.Minute * 5,
		stopChan:       make(chan struct{}),
	}

	// Initialize with default parameters
	for shardID := range metrics.shardMetrics {
		ac.params[shardID] = &ConsensusParams{
			BlockSize:        1000,
			ConfirmationTime: time.Second * 10,
			MinValidators:    3,
			Threshold:        0.67,
		}
	}

	return ac
}

func (ac *AdaptiveConsensus) Start() {
	go ac.adjustmentLoop()
}

func (ac *AdaptiveConsensus) Stop() {
	close(ac.stopChan)
}

func (ac *AdaptiveConsensus) adjustmentLoop() {
	ticker := time.NewTicker(ac.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ac.adjustParameters()
		case <-ac.stopChan:
			return
		}
	}
}

func (ac *AdaptiveConsensus) adjustParameters() {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	for shardID, metrics := range ac.metrics.shardMetrics {
		params := ac.params[shardID]

		// Adjust based on load
		loadFactor := metrics.LoadFactor
		switch {
		case loadFactor > 0.8: // High load
			params.BlockSize = 2000
			params.ConfirmationTime = time.Second * 5
			params.MinValidators = 5
			params.Threshold = 0.8
		case loadFactor > 0.4: // Medium load
			params.BlockSize = 1000
			params.ConfirmationTime = time.Second * 10
			params.MinValidators = 3
			params.Threshold = 0.67
		default: // Low load
			params.BlockSize = 500
			params.ConfirmationTime = time.Second * 15
			params.MinValidators = 2
			params.Threshold = 0.51
		}
	}
}

func (ac *AdaptiveConsensus) GetConsensusParams(shardID int) *ConsensusParams {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.params[shardID]
}
