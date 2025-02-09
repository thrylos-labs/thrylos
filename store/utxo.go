package store

import (
	"github.com/thrylos-labs/thrylos/shared"
)

// UTXOCache is a specialized wrapper around LRUCache that handles UTXO-specific operations.
// It provides type-safe methods for storing and retrieving UTXOs while utilizing the
// underlying LRU cache's memory management and bloom filter optimization.

// If a UTXO definitely doesn't exist, the bloom filter tells us immediately

type UTXOCache struct {
	cache *LRUCache
}

// UTXOCache is a specialized wrapper using LRUCache to store UTXOs
func NewUTXOCache(size int, bloomSize uint, falsePositiveRate float64) (*UTXOCache, error) {
	c, err := NewLRUCache(size, bloomSize, falsePositiveRate)
	if err != nil {
		return nil, err
	}
	return &UTXOCache{cache: c}, nil
}

func (uc *UTXOCache) Get(key string) (*shared.UTXO, bool) {
	value, ok := uc.cache.Get(key)
	if !ok {
		return nil, false
	}
	return value.(*shared.UTXO), true
}

func (uc *UTXOCache) Add(key string, utxo *shared.UTXO) bool {
	return uc.cache.Add(key, utxo)
}

func (uc *UTXOCache) Remove(key string) bool {
	return uc.cache.Remove(key)
}
