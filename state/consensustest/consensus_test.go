package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/thrylos-labs/thrylos/state"
)

func TestAdaptiveConsensus(t *testing.T) {
	// Use the embedded StateMetrics field instead of the wrapper type
	metricsImpl := state.NewStateMetrics(4)
	metrics := metricsImpl.StateMetrics // Get the embedded field

	ac := state.NewAdaptiveConsensus(metrics)

	t.Run("Parameter Adjustment", func(t *testing.T) {
		// Simulate high load - use a method to update load factor
		shardID := 0

		metrics.Mu.Lock()
		shardMetric := metrics.ShardMetrics[shardID]
		metrics.Mu.Unlock()

		shardMetric.UpdateLoadFactor(900)

		// Add a test method to expose adjustParameters
		// You'll need to add AdjustParametersForTesting to AdaptiveConsensusImpl
		ac.AdjustParametersForTesting()

		params := ac.GetConsensusParams(0)
		assert.Equal(t, 2000, params.BlockSize)
		assert.Equal(t, time.Second*5, params.ConfirmationTime)
		assert.Equal(t, 5, params.MinValidators)
		assert.Equal(t, 0.8, params.Threshold)
	})

	t.Run("Dynamic Adaptation", func(t *testing.T) {
		ac.Start()
		defer ac.Stop()

		// Simulate load changes
		shardID := 1

		metrics.Mu.Lock()
		shardMetric := metrics.ShardMetrics[shardID]
		metrics.Mu.Unlock()

		shardMetric.UpdateLoadFactor(300)

		// Wait a moment for the changes to take effect
		time.Sleep(time.Second)

		params := ac.GetConsensusParams(1)
		assert.Equal(t, 500, params.BlockSize)
		assert.Equal(t, time.Second*15, params.ConfirmationTime)
	})
}
