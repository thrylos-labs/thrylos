package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/thrylos-labs/thrylos/state"
)

func TestStateReallocation(t *testing.T) {
	mockNetwork := new(MockNetwork)
	mockNetwork.On("BroadcastMessage", mock.Anything).Return(nil)

	sm := state.NewStateManager(mockNetwork, 4)

	t.Run("Metrics Collection", func(t *testing.T) {
		address := "tl1test123"

		// Record some activity
		err := sm.UpdateState(address, 1000, nil)
		assert.NoError(t, err)

		balance, err := sm.GetBalance(address)
		assert.NoError(t, err)
		assert.Equal(t, int64(1000), balance)

		partition := sm.GetResponsiblePartition(address)

		// Use accessor methods to get metrics
		accessCount := sm.GetShardAccessCount(partition.ID)
		modifyCount := sm.GetShardModifyCount(partition.ID)
		loadFactor := sm.GetShardLoadFactor(partition.ID)

		assert.Equal(t, int64(1), accessCount)
		assert.Equal(t, int64(1), modifyCount)
		assert.True(t, loadFactor > 0)
	})

	t.Run("State Relocation", func(t *testing.T) {
		// Create an overloaded shard
		address := "tl1test456"
		partition := sm.GetResponsiblePartition(address)

		// You'll need to add methods to simulate high load
		// For example:
		err := sm.SimulateHighLoad(partition.ID, 1000) // Add this method to StateManagerImpl
		assert.NoError(t, err)

		// Add test state
		err = sm.UpdateState(address, 2000, nil)
		assert.NoError(t, err)

		// You need to expose the checkAndRelocate method or create a wrapper
		err = sm.CheckAndRelocateForTesting() // Add this method to StateManagerImpl
		assert.NoError(t, err)

		// Verify state was moved
		balance, err := sm.GetBalance(address)
		assert.NoError(t, err)
		assert.Equal(t, int64(2000), balance)
	})

	t.Run("Relocation Under Load", func(t *testing.T) {
		// Test concurrent access during relocation
		address := "tl1test789"

		// Add initial state
		err := sm.UpdateState(address, 3000, nil)
		assert.NoError(t, err)

		// Start concurrent operations
		done := make(chan bool)
		go func() {
			for i := 0; i < 100; i++ {
				sm.GetBalance(address)
				time.Sleep(time.Millisecond)
			}
			done <- true
		}()

		// Trigger relocation during operations
		err = sm.CheckAndRelocateForTesting()
		assert.NoError(t, err)

		<-done

		// Verify final state
		balance, err := sm.GetBalance(address)
		assert.NoError(t, err)
		assert.Equal(t, int64(3000), balance)
	})

	t.Run("Metrics Reset", func(t *testing.T) {
		address := "tl1test999"
		partition := sm.GetResponsiblePartition(address)

		// You'll need a method to record metrics
		err := sm.RecordMetricsForTesting(partition.ID) // Add this method to StateManagerImpl
		assert.NoError(t, err)

		// Verify metrics
		accessCount := sm.GetShardAccessCount(partition.ID)
		modifyCount := sm.GetShardModifyCount(partition.ID)

		assert.True(t, accessCount > 0)
		assert.True(t, modifyCount > 0)

		// You'll need a method to reset metrics
		err = sm.ResetMetricsForTesting(partition.ID) // Add this method to StateManagerImpl
		assert.NoError(t, err)

		accessCount = sm.GetShardAccessCount(partition.ID)
		modifyCount = sm.GetShardModifyCount(partition.ID)

		assert.Equal(t, int64(0), accessCount)
		assert.Equal(t, int64(0), modifyCount)
	})
}
