package store

import (
	"github.com/thrylos-labs/thrylos/shared"
)

type UTXOCache struct {
	cache *LRUCache
}

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
