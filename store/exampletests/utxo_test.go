package store

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/store"
)

func TestLRUCacheDirectly(t *testing.T) {
	lru, err := store.NewLRUCache(10, 100, 0.01)
	assert.NoError(t, err)
	assert.NotNil(t, lru)

	// Test with simple string key/value
	t.Run("Simple String Test", func(t *testing.T) {
		key := "test-key"
		value := "test-value"

		added := lru.Add(key, value)
		assert.True(t, added, "Failed to add string to LRU cache")

		retrieved, exists := lru.Get(key)
		assert.True(t, exists, "Failed to get string from LRU cache")
		assert.Equal(t, value, retrieved)
	})

	// Test with string key and interface value
	t.Run("Interface Value Test", func(t *testing.T) {
		type TestStruct struct {
			ID   string
			Data string
		}

		key := "test-struct-key"
		value := &TestStruct{ID: "1", Data: "test"}

		added := lru.Add(key, value)
		assert.True(t, added, "Failed to add struct to LRU cache")

		retrieved, exists := lru.Get(key)
		assert.True(t, exists, "Failed to get struct from LRU cache")

		retrievedStruct, ok := retrieved.(*TestStruct)
		assert.True(t, ok, "Failed to cast retrieved value")
		assert.Equal(t, value.ID, retrievedStruct.ID)
	})
}

// TestSimpleCache tests the most basic cache operations with detailed logging

func TestUTXOCache(t *testing.T) {
	cache, err := store.NewUTXOCache(100, 1000, 0.01)
	assert.NoError(t, err)
	assert.NotNil(t, cache)

	t.Run("Basic Operations", func(t *testing.T) {
		// Create a test UTXO
		utxo := shared.CreateUTXO(
			"test-utxo-1",
			0,
			"test-tx-1",
			"addr1_valid_address_format",
			100.0,
			false,
		)
		assert.NotNil(t, utxo)

		// Get the key
		key := utxo.Key()
		t.Logf("Using key: %s", key)

		// Add to cache
		added := cache.Add(key, utxo)
		assert.True(t, added, "Should add UTXO to cache")

		// Retrieve from cache
		retrieved, exists := cache.Get(key)
		assert.True(t, exists, "Should find UTXO in cache")
		assert.NotNil(t, retrieved, "Retrieved UTXO should not be nil")

		if retrieved != nil {
			assert.Equal(t, utxo.ID, retrieved.ID)
			assert.Equal(t, utxo.TransactionID, retrieved.TransactionID)
			assert.Equal(t, utxo.Index, retrieved.Index)
			assert.Equal(t, utxo.Amount, retrieved.Amount)
		}

		// Test removal
		removed := cache.Remove(key)
		assert.True(t, removed, "Should remove UTXO from cache")

		// Verify removal
		_, exists = cache.Get(key)
		assert.False(t, exists, "Should not find removed UTXO")
	})

	t.Run("Multiple UTXOs", func(t *testing.T) {
		// Test with multiple UTXOs
		for i := 0; i < 5; i++ {
			utxo := shared.CreateUTXO(
				fmt.Sprintf("utxo-%d", i),
				i,
				fmt.Sprintf("tx-%d", i),
				"addr1_valid_address_format",
				float64(100*(i+1)),
				false,
			)
			assert.NotNil(t, utxo)

			key := utxo.Key()
			t.Logf("Adding UTXO with key: %s", key)

			// Add to cache
			added := cache.Add(key, utxo)
			assert.True(t, added, "Should add UTXO %d to cache", i)

			// Verify immediately
			retrieved, exists := cache.Get(key)
			assert.True(t, exists, "Should find UTXO %d in cache", i)
			assert.NotNil(t, retrieved, "Retrieved UTXO %d should not be nil", i)

			if retrieved != nil {
				assert.Equal(t, utxo.ID, retrieved.ID)
				assert.Equal(t, utxo.TransactionID, retrieved.TransactionID)
				assert.Equal(t, utxo.Index, retrieved.Index)
				assert.Equal(t, utxo.Amount, retrieved.Amount)
			}
		}
	})
}

func TestUTXOCacheAdvanced(t *testing.T) {
	t.Run("Concurrent Access", func(t *testing.T) {
		cache, err := store.NewUTXOCache(1000, 10000, 0.01)
		assert.NoError(t, err)

		var wg sync.WaitGroup
		numGoroutines := 10
		numOperations := 100

		// Create concurrent writers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(routineID int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					utxo := shared.CreateUTXO(
						fmt.Sprintf("utxo-%d-%d", routineID, j),
						j,
						fmt.Sprintf("tx-%d-%d", routineID, j),
						"addr1_valid_address_format",
						float64(100*(j+1)),
						false,
					)
					key := utxo.Key()
					cache.Add(key, utxo)
				}
			}(i)
		}

		// Create concurrent readers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(routineID int) {
				defer wg.Done()
				for j := 0; j < numOperations; j++ {
					key := fmt.Sprintf("tx-%d-%d-%d", routineID, j, j)
					_, _ = cache.Get(key)
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("Cache Eviction", func(t *testing.T) {
		// Create a small cache to test eviction
		smallCacheSize := 5
		cache, err := store.NewUTXOCache(smallCacheSize, 100, 0.01)
		assert.NoError(t, err)

		// Add more items than the cache can hold
		addedUTXOs := make(map[string]*shared.UTXO)
		for i := 0; i < smallCacheSize*2; i++ {
			utxo := shared.CreateUTXO(
				fmt.Sprintf("utxo-%d", i),
				i,
				fmt.Sprintf("tx-%d", i),
				"addr1_valid_address_format",
				float64(100*(i+1)),
				false,
			)
			key := utxo.Key()
			cache.Add(key, utxo)
			addedUTXOs[key] = utxo

			// Small delay to ensure deterministic eviction order
			time.Sleep(time.Millisecond)
		}

		// Verify that older items were evicted
		evictedCount := 0
		for key := range addedUTXOs {
			_, exists := cache.Get(key)
			if !exists {
				evictedCount++
			}
		}
		assert.True(t, evictedCount >= smallCacheSize, "Expected at least %d items to be evicted", smallCacheSize)
	})

	t.Run("Cache Reuse After Removal", func(t *testing.T) {
		cache, err := store.NewUTXOCache(100, 1000, 0.01)
		assert.NoError(t, err)

		// Add and remove a UTXO
		utxo := shared.CreateUTXO("utxo-1", 0, "tx-1", "addr1_valid_address_format", 100.0, false)
		key := utxo.Key()

		added := cache.Add(key, utxo)
		assert.True(t, added)

		removed := cache.Remove(key)
		assert.True(t, removed)

		// Try to add a new UTXO with the same key
		newUTXO := shared.CreateUTXO("utxo-2", 0, "tx-1", "addr1_valid_address_format", 200.0, false)
		added = cache.Add(key, newUTXO)
		assert.True(t, added)

		// Verify the new UTXO is retrieved
		retrieved, exists := cache.Get(key)
		assert.True(t, exists)
		assert.Equal(t, newUTXO.ID, retrieved.ID)
		assert.Equal(t, newUTXO.Amount, retrieved.Amount)
	})

	t.Run("Error Handling", func(t *testing.T) {
		cache, err := store.NewUTXOCache(100, 1000, 0.01)
		assert.NoError(t, err)

		// Test with nil UTXO
		added := cache.Add("nil-key", nil)
		assert.True(t, added, "Should handle nil UTXO")

		// Test with empty key
		utxo := shared.CreateUTXO("utxo-1", 0, "", "addr1_valid_address_format", 100.0, false)
		key := utxo.Key()
		added = cache.Add(key, utxo)
		assert.True(t, added, "Should handle empty transaction ID")

		// Test with duplicate adds
		added = cache.Add(key, utxo)
		assert.True(t, added, "Should handle duplicate adds")

		// Test removing non-existent key
		removed := cache.Remove("non-existent-key")
		assert.True(t, removed, "Should handle non-existent key removal")

		// Test getting non-existent key
		_, exists := cache.Get("non-existent-key")
		assert.False(t, exists, "Should handle non-existent key get")
	})

	t.Run("Large Scale Operations", func(t *testing.T) {
		cache, err := store.NewUTXOCache(10000, 100000, 0.01)
		assert.NoError(t, err)

		// Add a large number of UTXOs
		numUTXOs := 1000
		for i := 0; i < numUTXOs; i++ {
			utxo := shared.CreateUTXO(
				fmt.Sprintf("utxo-%d", i),
				i,
				fmt.Sprintf("tx-%d", i),
				"addr1_valid_address_format",
				float64(100*(i+1)),
				false,
			)
			key := utxo.Key()
			added := cache.Add(key, utxo)
			assert.True(t, added)

			// Periodically verify random previously added UTXOs
			if i%100 == 0 && i > 0 {
				randomIndex := i - (i % 100)
				randomKey := fmt.Sprintf("tx-%d-%d", randomIndex, randomIndex)
				_, exists := cache.Get(randomKey)
				if exists {
					t.Logf("Successfully retrieved UTXO at index %d", randomIndex)
				}
			}
		}
	})
}
