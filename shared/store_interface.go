package shared

import (
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/consensus/validator"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

type Store interface {
	GetUTXO(addr address.Address) ([]*UTXO, error)
	GetTransaction(id string) (*Transaction, error)
	GetLastBlock() (*Block, error)
	GetLastBlockNumber() (int, error)
	GetBlock(blockNumber uint32) (*Block, error)
	GetPublicKey(addr address.Address) (crypto.PublicKey, error)
	GetValidator(addr address.Address) (*validator.Validator, error)

	RetrieveValidatorPublicKey(validatorAddress string) ([]byte, error)
	BeginTransaction() (*TransactionContext, error)
	RollbackTransaction(txn *TransactionContext) error
	MarkUTXOAsSpent(txContext *TransactionContext, utxo UTXO) error
	//writer
	UpdateUTXO(utxo *UTXO) error
	SaveTransaction(tx *Transaction) error
	SaveBlock(blk *Block) error
	UpdateValidator(v *validator.Validator) error
	AddNewUTXO(txContext *TransactionContext, utxo UTXO) error
	CommitTransaction(txn *TransactionContext) error
	GetUTXOsForAddress(address string) ([]UTXO, error)
	SetTransaction(txn *TransactionContext, key []byte, value []byte) error
	AddTransaction(tx *thrylos.Transaction) error
}
