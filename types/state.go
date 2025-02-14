package types

import (
	"sync"
	"time"
)

// // StatePartition represents the state data for a single shard
type StatePartition struct {
	ID           int
	StartAddress string
	EndAddress   string
	Balances     map[string]int64
	UTXOs        map[string]*UTXO
	LastUpdated  int64
	mu           sync.RWMutex
}

// StateManager handles state sharding across the network
type StateManager struct {
	partitions  []*StatePartition
	network     NetworkInterface
	totalShards int
	mu          sync.RWMutex
	stopChan    chan struct{}
	metrics     *StateMetrics
	consensus   *AdaptiveConsensus
	Scaling     *ShardScaling // Add this field (using capital S for public access)
}

type StateMetrics struct {
	ShardMetrics map[int]*ShardMetrics
	Mu           sync.RWMutex
}

type StateMetricsInterface interface {
	NewStateMetrics(numShards int) *StateMetrics
}

type ShardMetrics struct {
	AccessCount int64
	ModifyCount int64
	LoadFactor  float64
	Latency     time.Duration
	LastUpdated time.Time
	Mu          sync.RWMutex // Export the mutex
}

type ShardScaling struct {
	LoadThresholds struct {
		Split float64 // When to split a shard
		Merge float64 // When to consider merging shards
	}
	Limits struct {
		MinShards int
		MaxShards int
	}
	cooldownPeriod time.Duration
	lastScaleTime  time.Time
	mu             sync.RWMutex
}

type NetworkMessage struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

type ConsensusParams struct {
	BlockSize        int
	ConfirmationTime time.Duration
	MinValidators    int
	Threshold        float64
}

type AdaptiveConsensus struct {
	Params         map[int]*ConsensusParams
	Metrics        *StateMetrics
	UpdateInterval time.Duration
	StopChan       chan struct{}
	Mu             sync.RWMutex
}

type RelocationCandidate struct {
	Address     string
	AccessCount int64
	FromShard   int
	ToShard     int
}
