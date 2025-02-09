package shared

type TxPool interface {
	AddTransaction(tx *Transaction) error
	RemoveTransaction(tx *Transaction) error
	GetTransaction(txID string) (*Transaction, error)
	GetAllTransactions() ([]*Transaction, error)
	BroadcastTransaction(tx *Transaction) error
	Size() int
}
