package state

// func TestStateReallocation(t *testing.T) {
// 	mockNetwork := new(MockNetwork)
// 	mockNetwork.On("BroadcastMessage", mock.Anything).Return(nil)

// 	sm := state.NewStateManager(mockNetwork, 4)

// 	t.Run("Metrics Collection", func(t *testing.T) {
// 		address := "tl1test123"

// 		// Record some activity
// 		err := sm.UpdateState(address, 1000, nil)
// 		assert.NoError(t, err)

// 		balance, err := sm.GetBalance(address)
// 		assert.NoError(t, err)
// 		assert.Equal(t, int64(1000), balance)

// 		partition := sm.GetResponsiblePartition(address)
// 		metrics := sm.metrics.shardMetrics[partition.ID]

// 		assert.Equal(t, int64(1), metrics.AccessCount)
// 		assert.Equal(t, int64(1), metrics.ModifyCount)
// 		assert.True(t, metrics.LoadFactor > 0)
// 	})

// 	t.Run("State Relocation", func(t *testing.T) {
// 		// Create an overloaded shard
// 		address := "tl1test456"
// 		partition := sm.GetResponsiblePartition(address)

// 		// Simulate high load
// 		for i := 0; i < 1000; i++ {
// 			sm.metrics.shardMetrics[partition.ID].RecordAccess()
// 			sm.metrics.shardMetrics[partition.ID].RecordModify()
// 		}
// 		sm.metrics.shardMetrics[partition.ID].UpdateLoadFactor(900)

// 		// Add test state
// 		err := sm.UpdateState(address, 2000, nil)
// 		assert.NoError(t, err)

// 		// Trigger relocation check
// 		sm.checkAndRelocate()

// 		// Verify state was moved
// 		balance, err := sm.GetBalance(address)
// 		assert.NoError(t, err)
// 		assert.Equal(t, int64(2000), balance)
// 	})

// 	t.Run("Relocation Under Load", func(t *testing.T) {
// 		// Test concurrent access during relocation
// 		address := "tl1test789"

// 		// Add initial state
// 		err := sm.UpdateState(address, 3000, nil)
// 		assert.NoError(t, err)

// 		// Start concurrent operations
// 		done := make(chan bool)
// 		go func() {
// 			for i := 0; i < 100; i++ {
// 				sm.GetBalance(address)
// 				time.Sleep(time.Millisecond)
// 			}
// 			done <- true
// 		}()

// 		// Trigger relocation during operations
// 		sm.checkAndRelocate()

// 		<-done

// 		// Verify final state
// 		balance, err := sm.GetBalance(address)
// 		assert.NoError(t, err)
// 		assert.Equal(t, int64(3000), balance)
// 	})

// 	t.Run("Metrics Reset", func(t *testing.T) {
// 		address := "tl1test999"
// 		partition := sm.GetResponsiblePartition(address)

// 		// Record metrics
// 		sm.metrics.shardMetrics[partition.ID].RecordAccess()
// 		sm.metrics.shardMetrics[partition.ID].RecordModify()

// 		// Verify metrics
// 		metrics := sm.metrics.shardMetrics[partition.ID]
// 		assert.True(t, metrics.AccessCount > 0)
// 		assert.True(t, metrics.ModifyCount > 0)

// 		// Reset metrics
// 		metrics.AccessCount = 0
// 		metrics.ModifyCount = 0

// 		assert.Equal(t, int64(0), metrics.AccessCount)
// 		assert.Equal(t, int64(0), metrics.ModifyCount)
// 	})
// }
