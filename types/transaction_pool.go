package types

import (
	"container/list"
	"sync"
)

type txPool struct {
	mu           sync.RWMutex
	transactions map[string]*list.Element
	order        *list.List
	db           *Store                 // Add database reference
	propagator   *TransactionPropagator // Add propagator
}

type txEntry struct {
	txID string
	tx   *Transaction
}

type TransactionPropagator struct {
	blockchain BlockchainInterface // Changed from *Blockchain to BlockchainInterface
	mu         sync.RWMutex
}

type TxPool interface {
	AddTransaction(tx *Transaction) error
	RemoveTransaction(tx *Transaction) error
	GetTransaction(txID string) (*Transaction, error)
	GetFirstTransaction() (*Transaction, error)
	GetAllTransactions() ([]*Transaction, error)
	BroadcastTransaction(tx *Transaction) error
	Size() int
}
