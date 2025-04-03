package types

import (
	"math/big"
	"sync"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/crypto"
)

// // // Blockchain represents the entire blockchain structure, encapsulating all blocks, stakeholders,
// // // and transactions within the network. It serves as the central ledger of the system, tracking
// // // the state of the blockchain, including ownership of assets through UTXOs (Unspent Transaction Outputs),
// // // and the resolution of forks, ensuring the integrity and continuity of the chain.
type Blockchain struct {
	// Blocks holds the sequence of blocks that constitute the blockchain. Each block contains
	// a set of transactions and is linked to the previous block, forming the chain.
	Blocks []*Block

	// Genesis points to the first block in the blockchain, known as the Genesis block. This block
	// is the foundation of the blockchain, with no preceding block.
	Genesis *Block

	// Adding transactions to the pending transactions pool
	PendingTransactions []*thrylos.Transaction

	// Stakeholders maps validator addresses to their respective stakes in the network. This is
	// used in proof-of-stake (PoS) consensus mechanisms to determine validators' rights to create
	// new blocks based on the size of their stake
	Stakeholders map[string]int64 // Maps validator addresses to their respective stakes

	// UTXOs tracks unspent transaction outputs, which represent the current state of ownership
	// of the blockchain's assets. It is a key component in preventing double spending.
	UTXOs map[string][]*thrylos.UTXO

	// Forks captures any divergences in the blockchain, where two or more blocks are found to
	// have the same predecessor. Forks are resolved through mechanisms that ensure consensus
	// on a single chain.
	Forks []*Fork

	// Mu provides concurrency control to ensure that operations on the blockchain are thread-safe,
	// preventing race conditions and ensuring data integrity.
	Mu sync.RWMutex

	// lastTimestamp records the timestamp of the last added block. This is used to ensure that
	// blocks are added in chronological order, preserving the integrity of the blockchain's timeline.
	LastTimestamp int64

	// Database provides an abstraction over the underlying database technology used to persist
	// blockchain data, facilitating operations like adding blocks and retrieving blockchain state
	Database Store // Updated the type to interface

	PublicKeyMap map[string]*crypto.PublicKey // To store public keys

	GenesisAccount crypto.PrivateKey // Add this to store the genesis account address

	ConsensusManager *ConsensusManager

	ActiveValidators []string

	MinStakeForValidator *big.Int

	OnNewBlock func(*Block) // Callback function for when a new block is added

	ValidatorKeys          ValidatorKeyStore // Changed from *ValidatorKeyStore to ValidatorKeyStore
	TestMode               bool
	OnTransactionProcessed func(*thrylos.Transaction)
	OnBalanceUpdate        func(address string, balance int64)

	StateManager *StateManager

	StateNetwork   NetworkInterface
	StakingService *StakingService

	TransactionPropagator *TransactionPropagator
}

// // Fork structure representing a fork in the blockchain
type Fork struct {
	Index  int
	Blocks []*Block
}

// NewTransaction creates a new transaction
type Stakeholder struct {
	Address string
	Stake   int
}

type BlockchainConfig struct {
	DataDir           string
	AESKey            []byte
	GenesisAccount    crypto.PrivateKey
	TestMode          bool
	DisableBackground bool
	StateManager      *StateManager
}
