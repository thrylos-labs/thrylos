package state

import (
	"crypto/rsa"

	"github.com/thrylos-labs/thrylos"
)

type StateInterface interface {
	SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error)
	AddTransaction(tx *thrylos.Transaction) error
	UpdateUTXOs(inputs []UTXO, outputs []UTXO) error
	CreateUTXO(id, txID string, index int, address string, amount int64) (UTXO, error)
	GetUTXOsForUser(address string) ([]UTXO, error)
	GetUTXOs(address string) (map[string][]UTXO, error)
	CreateAndSignTransaction(txID string, inputs, outputs []UTXO, privKey *rsa.PrivateKey) (Transaction, error)
	RetrieveMLDSAPublicKey(address string) ([]byte, error)
	CommitTransaction(txn *TransactionContext) error
	RollbackTransaction(txn *TransactionContext) error
	SetTransaction(txn *TransactionContext, key []byte, value []byte) error
}
