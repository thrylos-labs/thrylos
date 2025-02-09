package store

import (
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/willf/bloom"
)

// The cache is particularly useful for storing blockchain transaction data (UTXOs)
// because it provides quick access to active transaction outputs while automatically
// managing memory by removing inactive ones.

// UTXOCache is a specialized wrapper using LRUCache to store UTXOs
type LRUCache struct {
	cache       *lru.Cache[string, interface{}] // Updated to use generics
	bloomFilter *bloom.BloomFilter
	mutex       sync.RWMutex
}

// NewLRUCache creates a new LRU cache with a Bloom filter
func NewLRUCache(size int, expectedItems uint, falsePositiveRate float64) (*LRUCache, error) {
	// Create new LRU cache with string keys and interface{} values
	c, err := lru.New[string, interface{}](size)
	if err != nil {
		return nil, err
	}

	// Create Bloom filter
	bf := bloom.NewWithEstimates(expectedItems, falsePositiveRate)

	return &LRUCache{
		cache:       c,
		bloomFilter: bf,
	}, nil
}

// Get retrieves a value from the cache
func (c *LRUCache) Get(key interface{}) (interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	keyStr, ok := key.(string)
	if !ok {
		return nil, false
	}

	if !c.bloomFilter.TestString(keyStr) {
		return nil, false
	}

	return c.cache.Get(keyStr)
}

// Add adds a value to the cache
func (c *LRUCache) Add(key interface{}, value interface{}) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	keyStr, ok := key.(string)
	if !ok {
		return false
	}

	// Add to bloom filter first
	c.bloomFilter.AddString(keyStr)

	// Add to cache
	c.cache.Add(keyStr, value)
	return true
}

// Remove removes a value from the cache
func (c *LRUCache) Remove(key interface{}) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	keyStr, ok := key.(string)
	if !ok {
		return false
	}

	c.cache.Remove(keyStr)
	return true
}

// Purge clears all items from the cache
func (c *LRUCache) Purge() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache.Purge()
	c.bloomFilter.ClearAll()
}
