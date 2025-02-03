package state

import (
	"time"

	"github.com/thrylos-labs/thrylos/shared"
)

type AdaptiveConsensusImpl struct {
	*shared.AdaptiveConsensus
}

func NewAdaptiveConsensus(metrics *shared.StateMetrics) *AdaptiveConsensusImpl {
	ac := &shared.AdaptiveConsensus{
		Params:         make(map[int]*shared.ConsensusParams),
		Metrics:        metrics,
		UpdateInterval: time.Minute * 5,
		StopChan:       make(chan struct{}),
	}

	for shardID := range metrics.ShardMetrics {
		ac.Params[shardID] = &shared.ConsensusParams{
			BlockSize:        1000,
			ConfirmationTime: time.Second * 10,
			MinValidators:    3,
			Threshold:        0.67,
		}
	}

	return &AdaptiveConsensusImpl{
		AdaptiveConsensus: ac,
	}
}

func (ac *AdaptiveConsensusImpl) Start() {
	go ac.adjustmentLoop()
}

func (ac *AdaptiveConsensusImpl) Stop() {
	close(ac.StopChan)
}

func (ac *AdaptiveConsensusImpl) adjustmentLoop() {
	ticker := time.NewTicker(ac.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ac.adjustParameters()
		case <-ac.StopChan:
			return
		}
	}
}

func (ac *AdaptiveConsensusImpl) adjustParameters() {
	ac.Mu.Lock()
	defer ac.Mu.Unlock()

	for shardID, metrics := range ac.Metrics.ShardMetrics {
		params := ac.Params[shardID]

		loadFactor := metrics.LoadFactor
		switch {
		case loadFactor > 0.8:
			params.BlockSize = 2000
			params.ConfirmationTime = time.Second * 5
			params.MinValidators = 5
			params.Threshold = 0.8
		case loadFactor > 0.4:
			params.BlockSize = 1000
			params.ConfirmationTime = time.Second * 10
			params.MinValidators = 3
			params.Threshold = 0.67
		default:
			params.BlockSize = 500
			params.ConfirmationTime = time.Second * 15
			params.MinValidators = 2
			params.Threshold = 0.51
		}
	}
}

func (ac *AdaptiveConsensusImpl) GetConsensusParams(shardID int) *shared.ConsensusParams {
	ac.Mu.RLock()
	defer ac.Mu.RUnlock()
	return ac.Params[shardID]
}
