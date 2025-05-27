// types/sharding.go
package types

import (
	"math/big"
	"sync"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/crypto"
)

// ShardID type (new)
type ShardID int

// ChainState represents the state specific to a single shard chain.
// This is effectively your current 'types.Blockchain' struct, but renamed and modified.
type ChainState struct {
	ShardID        ShardID // Identifier for this shard
	TotalNumShards int     // NEW: Total number of shards in the network
	Blocks         []*Block
	Genesis        *Block

	// PendingTransactions: Will be moved to a shard-specific TxPool.
	PendingTransactions    []*thrylos.Transaction
	Stakeholders           map[string]int64
	UTXOs                  map[string][]*thrylos.UTXO // Still uses *thrylos.UTXO internally
	Forks                  []*Fork                    // Forks within this specific shard chain
	Mu                     sync.RWMutex               // This mutex protects only THIS shard's state
	LastTimestamp          int64
	Database               Store // Store interface, but implementation will be shard-aware
	PublicKeyMap           map[string]*crypto.PublicKey
	GenesisAccount         crypto.PrivateKey
	ConsensusManager       *ConsensusManager
	ActiveValidators       []string
	NextValidatorIndex     int
	MinStakeForValidator   *big.Int
	OnNewBlock             func(*Block)
	ValidatorKeys          ValidatorKeyStore
	TestMode               bool
	OnTransactionProcessed func(*thrylos.Transaction)
	OnBalanceUpdate        func(address string, balance int64)
	StateManager           *StateManager
	StateNetwork           NetworkInterface
	StakingService         *StakingService
	TransactionPropagator  *TransactionPropagator
}

// BeaconChain represents the global coordination chain.
type BeaconChain struct {
	// Blocks specific to the Beacon Chain
	Blocks   []*Block
	Mu       sync.RWMutex
	Database Store // Dedicated DB for beacon chain
	// Global validator registry, cross-shard transaction proofs, etc.
	// Could also manage shard assignments to validators.
}
