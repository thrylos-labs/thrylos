package shared

import (
	"crypto/rsa"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

type Store interface {
	//UTOX
	GetUTXO(addr address.Address) ([]*UTXO, error)
	AddUTXO(utxo UTXO) error
	GetAllUTXOs() (map[string][]UTXO, error)
	AddNewUTXO(txContext *TransactionContext, utxo UTXO) error //why do we need this?
	CreateAndStoreUTXO(id, txID string, index int, owner string, amount float64) error
	CreateUTXO(id, txID string, index int, address string, amount float64) (UTXO, error)
	UpdateUTXOs(inputs []UTXO, outputs []UTXO) error
	MarkUTXOAsSpent(txContext *TransactionContext, utxo UTXO) error

	//Transaction
	GetTransaction(id string) (*Transaction, error)
	ProcessTransaction(tx *Transaction) error
	SetTransaction(txn *TransactionContext, key []byte, value []byte) error
	SaveTransaction(tx *Transaction) error
	TransactionExists(txn *TransactionContext, txID string) (bool, error)
	CommitTransaction(txn *TransactionContext) error
	AddTransaction(tx *thrylos.Transaction) error
	SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error)
	BeginTransaction() (*TransactionContext, error)
	RollbackTransaction(txn *TransactionContext) error

	//Block
	GetLastBlock() (*Block, error)
	GetLastBlockNumber() (int, error)
	GetBlock(blockNumber uint32) (*Block, error)
	SaveBlock(blk *Block) error
	GetLastBlockData() ([]byte, error)
	GetLastBlockIndex() (int, error)

	//Validator
	GetValidator(addr address.Address) (*Validator, error)
	SaveValidator(v *Validator) error

	//PublicKey
	GetPublicKey(addr address.Address) (crypto.PublicKey, error)
	SavePublicKey(pubKey crypto.PublicKey) error
}
