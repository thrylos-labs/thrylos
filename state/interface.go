package state

import (
	"crypto/rsa"

	"github.com/thrylos-labs/thrylos/shared"
)

type StateInterface interface {
	SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error)
	AddTransaction(tx *shared.Transaction) error
	UpdateUTXOs(inputs []*shared.UTXO, outputs []*shared.UTXO) error
	CreateUTXO(id, txID string, index int, address string, amount int64) (*shared.UTXO, error)
	GetUTXOsForUser(address string) ([]*shared.UTXO, error)
	GetUTXOs(address string) (map[string][]*shared.UTXO, error)
	CreateAndSignTransaction(txID string, inputs, outputs []*shared.UTXO, privKey *rsa.PrivateKey) (*shared.Transaction, error)
	RetrieveMLDSAPublicKey(address string) ([]byte, error)
	// CommitTransaction(txn *TransactionContext) error
	// RollbackTransaction(txn *TransactionContext) error
	// SetTransaction(txn *TransactionContext, key []byte, value []byte) error
}
