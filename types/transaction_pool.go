package types

import (
	"sync"
)

type TransactionPropagator struct {
	Blockchain BlockchainInterface
	Mu         sync.RWMutex
}

type TxPool interface {
	AddTransaction(tx *Transaction) error
	RemoveTransaction(tx *Transaction) error
	GetTransaction(txID string) (*Transaction, error)
	GetFirstTransaction() (*Transaction, error)
	GetAllTransactions() ([]*Transaction, error)
	BroadcastTransaction(tx *Transaction) error
	// GetActiveValidators(tx *Transaction) error
	Size() int
}
