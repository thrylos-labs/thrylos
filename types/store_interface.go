package types

import (
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
	AddNewUTXO(txContext TransactionContext, utxo UTXO) error
	CreateAndStoreUTXO(id, txID string, index int, owner string, amount float64) error
	CreateUTXO(id, txID string, index int, address string, amount float64) (UTXO, error)
	UpdateUTXOs(inputs []UTXO, outputs []UTXO) error
	GetUTXOsForAddress(address string) ([]UTXO, error)
	GetUTXOsForUser(address string) ([]UTXO, error)
	RetrieveBlock(blockNumber int) ([]byte, error)
	MarkUTXOAsSpent(txContext TransactionContext, utxo UTXO) error

	//Transaction
	GetTransaction(id string) (*Transaction, error)
	ProcessTransaction(tx *Transaction) error
	SetTransaction(txn TransactionContext, key []byte, value []byte) error
	SaveTransaction(tx *Transaction) error

	TransactionExists(txContext TransactionContext, txID string) (bool, error)

	CommitTransaction(ctx TransactionContext) error
	AddTransaction(tx *thrylos.Transaction) error
	SendTransaction(fromAddress, toAddress string, amount int, privKey crypto.PrivateKey) (bool, error)
	BeginTransaction() (TransactionContext, error)
	RollbackTransaction(txn TransactionContext) error

	//Block
	GetLastBlock() (*Block, error)
	GetLastBlockNumber() (int, error)
	GetBlock(blockNumber uint32) (*Block, error)
	GetLastBlockData() ([]byte, error)
	GetLastBlockIndex() (int, error)
	StoreBlock(blockData []byte, blockNumber int) error

	SaveBlock(blk *Block) error                                                 // For Genesis
	SaveBlockWithContext(ctx TransactionContext, blk *Block) error              // For AddBlockToChain
	AddToBalance(ctx TransactionContext, address string, amount int64) error    // New method
	SpendUTXO(ctx TransactionContext, utxoKey string) (amount int64, err error) // New method

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
