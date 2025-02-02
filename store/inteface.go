package store

import (
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos"
)

type BlockStoreInterface interface {
	InsertBlock(data []byte, blockNumber int) error
	GetLastBlockData() ([]byte, int, error)
	InsertOrUpdateMLDSAPublicKey(address string, mldsaPublicKey *mldsa44.PublicKey) error
	StoreBlock(data []byte, blockNumber int) error
	RetrieveBlock(blockNumber int) ([]byte, error)
	BeginTransaction() (*TransactionContext, error)
}

type TransactionStoreInterface interface {
	GetBalance(address string, utxos map[string][]UTXO) (int64, error)
	RetrievePublicKeyFromAddress(address string) (*mldsa44.PublicKey, error)
	AddTransaction(tx *thrylos.Transaction) error
	UpdateUTXOs(inputs []UTXO, outputs []UTXO) error
	CreateUTXO(id, txID string, index int, address string, amount int64) (UTXO, error)
	GetUTXOsForUser(address string) ([]UTXO, error)
	GetUTXOs(address string) (map[string][]UTXO, error)
	BeginTransaction() (*TransactionContext, error)
	CommitTransaction(txn *TransactionContext) error
	RollbackTransaction(txn *TransactionContext) error
	SetTransaction(txn *TransactionContext, key []byte, value []byte) error
	GetUTXOsByAddress(address string) (map[string][]UTXO, error)
	GetAllUTXOs() (map[string][]UTXO, error)
	GetUTXOsForAddress(address string) ([]UTXO, error)
	AddUTXO(utxo UTXO) error // Add this line
	TransactionExists(txn *TransactionContext, txID string) (bool, error)
	MarkUTXOAsSpent(txn *TransactionContext, utxo UTXO) error
	AddNewUTXO(txn *TransactionContext, utxo UTXO) error
}

type ValidatorStoreIntraface interface {
	StoreValidatorPublicKey(validatorAddress string, publicKey []byte) error
	RetrieveValidatorPublicKey(validatorAddress string) ([]byte, error)
}
