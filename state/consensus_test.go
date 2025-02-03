package state

// import (
// 	"testing"
// 	"time"

// 	"github.com/stretchr/testify/assert"
// )

// func TestAdaptiveConsensus(t *testing.T) {
// 	metrics := NewStateMetrics(4)
// 	ac := NewAdaptiveConsensus(metrics)

// 	t.Run("Parameter Adjustment", func(t *testing.T) {
// 		// Simulate high load
// 		metrics.shardMetrics[0].UpdateLoadFactor(900)

// 		// Trigger adjustment
// 		ac.adjustParameters()

// 		params := ac.GetConsensusParams(0)
// 		assert.Equal(t, 2000, params.BlockSize)
// 		assert.Equal(t, time.Second*5, params.ConfirmationTime)
// 		assert.Equal(t, 5, params.MinValidators)
// 		assert.Equal(t, 0.8, params.Threshold)
// 	})

// 	t.Run("Dynamic Adaptation", func(t *testing.T) {
// 		ac.Start()
// 		defer ac.Stop()

// 		// Simulate load changes
// 		metrics.shardMetrics[1].UpdateLoadFactor(300)
// 		time.Sleep(time.Second)

// 		params := ac.GetConsensusParams(1)
// 		assert.Equal(t, 500, params.BlockSize)
// 		assert.Equal(t, time.Second*15, params.ConfirmationTime)
// 	})
// }
