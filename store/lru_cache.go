package store

import (
	"sync"

	lru "github.com/hashicorp/golang-lru"
	"github.com/willf/bloom"
)

type Cache interface {
	Get(key interface{}) (interface{}, bool)
	Add(key, value interface{}) bool
	Remove(key interface{}) bool
	Purge()
}

type LRUCache struct {
	cache       *lru.Cache
	bloomFilter *bloom.BloomFilter
	mutex       sync.Mutex
}

func NewLRUCache(size int, bloomFilterSize uint, bloomFilterHashes uint) (*LRUCache, error) {
	c, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	bf := bloom.New(bloomFilterHashes, bloomFilterSize)
	return &LRUCache{cache: c, bloomFilter: bf}, nil
}

func (c *LRUCache) Get(key interface{}) (interface{}, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !c.bloomFilter.Test([]byte(key.(string))) {
		return nil, false
	}
	return c.cache.Get(key)
}

func (c *LRUCache) Add(key, value interface{}) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.bloomFilter.Add([]byte(key.(string)))
	return c.cache.Add(key, value)
}

func (c *LRUCache) Remove(key interface{}) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.cache.Remove(key)
}

func (c *LRUCache) Purge() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache.Purge()
	c.bloomFilter.ClearAll()
}
