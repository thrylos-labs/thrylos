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

func (sm *StateManager) Unlock() {
	sm.mu.Unlock()
}

func (sm *StateManager) Lock() {
	sm.mu.Lock()
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

// In the types package, change:
type ShardScaling struct {
	LoadThresholds struct {
		Split float64 // When to split a shard
		Merge float64 // When to consider merging shards
	}
	Limits struct {
		MinShards int
		MaxShards int
	}
	CooldownPeriod time.Duration // Now exported with capital C
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

func (sm *StateManager) GetStopChan() <-chan struct{} {
	return sm.stopChan
}

// In the types package, add these methods:

// Access to StateManager's fields
func (sm *StateManager) GetPartitions() []*StatePartition {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.partitions
}

func (sm *StateManager) PartitionsCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.partitions)
}

func (sm *StateManager) GetShardLoadFactor(shardID int) float64 {
	// Implementation of load factor calculation
	sm.metrics.Mu.RLock()
	defer sm.metrics.Mu.RUnlock()

	if metrics, ok := sm.metrics.ShardMetrics[shardID]; ok {
		metrics.Mu.RLock()
		defer metrics.Mu.RUnlock()
		return metrics.LoadFactor
	}
	return 0
}

// Access to ShardScaling's fields
func (s *ShardScaling) GetCooldownPeriod() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CooldownPeriod // Changed from cooldownPeriod to CooldownPeriod
}

func (s *ShardScaling) SetLastScaleTime(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastScaleTime = t
}

func (s *ShardScaling) GetLastScaleTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastScaleTime
}

func (s *ShardScaling) Lock() {
	s.mu.Lock()
}

func (s *ShardScaling) Unlock() {
	s.mu.Unlock()
}

// Add these methods to your types/state.go file

// GetMutex returns the state manager's mutex
func (sm *StateManager) GetMutex() *sync.RWMutex {
	return &sm.mu
}

// GetMetrics returns the state metrics
func (sm *StateManager) GetMetrics() *StateMetrics {
	return sm.metrics
}

// GetPartition returns a partition by ID
func (sm *StateManager) GetPartition(id int) *StatePartition {
	if id >= 0 && id < len(sm.partitions) {
		return sm.partitions[id]
	}
	return nil
}

// GetShardMetrics returns the metrics for a specific shard
func (sm *StateManager) GetShardMetrics(shardID int) *ShardMetrics {
	if sm.metrics != nil && sm.metrics.ShardMetrics != nil {
		return sm.metrics.ShardMetrics[shardID]
	}
	return nil
}

// Add these methods to your ShardMetrics struct in the types package

// RecordAccess increments the access count for this shard
func (sm *ShardMetrics) RecordAccess() {
	sm.Mu.Lock()
	defer sm.Mu.Unlock()
	sm.AccessCount++
	sm.LastUpdated = time.Now()
}

// RecordModify increments the modify count for this shard
func (sm *ShardMetrics) RecordModify() {
	sm.Mu.Lock()
	defer sm.Mu.Unlock()
	sm.ModifyCount++
	sm.LastUpdated = time.Now()
}

// UpdateLoadFactor updates the load factor based on the current state
func (sm *ShardMetrics) UpdateLoadFactor(itemCount int) {
	sm.Mu.Lock()
	defer sm.Mu.Unlock()
	// Simple load factor calculation - can be customized
	baseline := 1000 // Assuming 1000 items is the baseline
	sm.LoadFactor = float64(itemCount) / float64(baseline)
}

// Add these methods to your StatePartition struct in the types package

// RLock acquires a read lock on the partition
func (p *StatePartition) RLock() {
	p.mu.RLock()
}

// RUnlock releases a read lock on the partition
func (p *StatePartition) RUnlock() {
	p.mu.RUnlock()
}

// Lock acquires a write lock on the partition
func (p *StatePartition) Lock() {
	p.mu.Lock()
}

// Unlock releases a write lock on the partition
func (p *StatePartition) Unlock() {
	p.mu.Unlock()
}

// GetBalances returns a copy of the balances map
func (p *StatePartition) GetBalances() map[string]int64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Return a copy to avoid race conditions
	balances := make(map[string]int64, len(p.Balances))
	for addr, amount := range p.Balances {
		balances[addr] = amount
	}
	return balances
}

// GetUTXOs returns a copy of the UTXOs map
func (p *StatePartition) GetUTXOs() map[string]*UTXO {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Return a copy to avoid race conditions
	utxos := make(map[string]*UTXO, len(p.UTXOs))
	for id, utxo := range p.UTXOs {
		utxos[id] = utxo
	}
	return utxos
}

// Add these methods to your types package for the StateManager

// CloseStopChan safely closes the stop channel
func (sm *StateManager) CloseStopChan() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	close(sm.stopChan)
}

// GetNetwork returns the network interface
func (sm *StateManager) GetNetwork() NetworkInterface {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.network
}

// GetConsensus returns the consensus mechanism
func (sm *StateManager) GetConsensus() *AdaptiveConsensus {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.consensus
}

// SetPartitions sets the partitions
func (sm *StateManager) SetPartitions(partitions []*StatePartition) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.partitions = partitions
}

// SetNetwork sets the network interface
func (sm *StateManager) SetNetwork(network NetworkInterface) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.network = network
}

// SetTotalShards sets the total number of shards
func (sm *StateManager) SetTotalShards(totalShards int) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.totalShards = totalShards
}

// InitStopChan initializes the stop channel
func (sm *StateManager) InitStopChan() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.stopChan = make(chan struct{})
}

// SetMetrics sets the metrics
func (sm *StateManager) SetMetrics(metrics *StateMetrics) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.metrics = metrics
}

// SetConsensus sets the consensus mechanism
func (sm *StateManager) SetConsensus(consensus *AdaptiveConsensus) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.consensus = consensus
}

// SetScaling sets the shard scaling
func (sm *StateManager) SetScaling(scaling *ShardScaling) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.Scaling = scaling
}

// UpdatePartition updates a partition at a specific index
func (sm *StateManager) UpdatePartition(index int, partition *StatePartition) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if index >= 0 && index < len(sm.partitions) {
		sm.partitions[index] = partition
	}
}
