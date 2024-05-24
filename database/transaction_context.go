package database

import "github.com/dgraph-io/badger"

type TransactionContext struct {
	Txn *badger.Txn
}

func NewTransactionContext(txn *badger.Txn) *TransactionContext {
	return &TransactionContext{Txn: txn}
}
