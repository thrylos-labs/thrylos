package types

import (
	badger "github.com/dgraph-io/badger/v3"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

type Store interface {
	//UTOX
	GetUTXO(addr address.Address) ([]*UTXO, error)
	AddUTXO(utxo UTXO) error
	GetAllUTXOs() (map[string][]UTXO, error)
	AddNewUTXO(ctx TransactionContext, utxo UTXO, totalNumShards int) error
	CreateAndStoreUTXO(id, txID string, index int, owner string, amount float64) error
	CreateUTXO(id, txID string, index int, address string, amount float64) (UTXO, error)
	UpdateUTXOs(inputs []UTXO, outputs []UTXO) error
	GetUTXOsForUser(address string) ([]UTXO, error)
	GetUTXOsForAddress(address string, totalNumShards int) ([]UTXO, error)
	MarkUTXOAsSpent(ctx TransactionContext, utxo UTXO, totalNumShards int) error

	//Transaction

	RetrieveTransaction(txn *badger.Txn, transactionID string, shardID ShardID) (*Transaction, error)
	SendTransaction(fromAddress, toAddress string, amount int, privKey crypto.PrivateKey, totalNumShards int) (bool, error) // MODIFIED
	SaveTransaction(ctx TransactionContext, tx *Transaction, totalNumShards int) error                                      // MODIFIED (added ctx to align with common usage)
	GetTransaction(id string, shardID ShardID) (*Transaction, error)                                                        // MODIFIED
	ProcessTransaction(tx *Transaction, totalNumShards int) error                                                           // MODIFIED (assuming it orchestrates other sharded ops)
	AddTransaction(tx *thrylos.Transaction, shardID ShardID) error                                                          // MODIFIED (if thrylos.Transaction is stored directly per-shard)
	TransactionExists(ctx TransactionContext, txID string, shardID ShardID) (bool, error)                                   // MODIFIED
	SetTransaction(txn TransactionContext, key []byte, value []byte) error

	CommitTransaction(ctx TransactionContext) error
	BeginTransaction() (TransactionContext, error)
	RollbackTransaction(txn TransactionContext) error

	//Block
	GetLastBlock() (*Block, error)
	GetLastBlockNumber() (int, error)
	GetBlock(blockNumber uint32) (*Block, error)
	RetrieveBlock(shardID ShardID, blockNumber int) ([]byte, error) // MODIFIED: Added shardID

	GetLastBlockData(shardID ShardID) ([]byte, error)
	StoreBlock(blockData []byte, blockNumber int) error
	GetLastBlockIndex(shardID ShardID) (int, error)
	SaveBlock(blk *Block) error                                    // For Genesis
	SaveBlockWithContext(ctx TransactionContext, blk *Block) error // For AddBlockToChain
	AddToBalance(ctx TransactionContext, address string, amount int64, totalNumShards int) error
	SpendUTXO(ctx TransactionContext, utxoKey string, ownerAddress string, totalNumShards int) (amount int64, err error)
	//Validator
	// GetValidator(addr address.Address) (*Validator, error)
	// SaveValidator(v *Validator) error

	//PublicKey
	GetPublicKey(addr address.Address) (crypto.PublicKey, error)
	SavePublicKey(pubKey crypto.PublicKey) error

	//Balance
	GetBalance(address string, utxos map[string][]UTXO) (amount.Amount, error)
	UpdateBalance(address string, balance int64) error

	// Close
	Close() error
	GetDataDir() string
	GetLockFilePath() string
}
