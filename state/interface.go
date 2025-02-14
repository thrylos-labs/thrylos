package state

import (
	"crypto/rsa"

	"github.com/thrylos-labs/thrylos/types"
)

type StateInterface interface {
	SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error)
	AddTransaction(tx *types.Transaction) error
	UpdateUTXOs(inputs []*types.UTXO, outputs []*types.UTXO) error
	CreateUTXO(id, txID string, index int, address string, amount int64) (*types.UTXO, error)
	GetUTXOsForUser(address string) ([]*types.UTXO, error)
	GetUTXOs(address string) (map[string][]*types.UTXO, error)
	CreateAndSignTransaction(txID string, inputs, outputs []*types.UTXO, privKey *rsa.PrivateKey) (*types.Transaction, error)
	RetrieveMLDSAPublicKey(address string) ([]byte, error)
	// CommitTransaction(txn *TransactionContext) error
	// RollbackTransaction(txn *TransactionContext) error
	// SetTransaction(txn *TransactionContext, key []byte, value []byte) error
}
