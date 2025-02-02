package state

// import (
// 	"crypto/rsa"

// 	"github.com/thrylos-labs/thrylos/chain"
// )

// type StateInterface interface {
// 	SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error)
// 	AddTransaction(tx *chain.Transaction) error
// 	UpdateUTXOs(inputs []*chain.UTXO, outputs []*chain.UTXO) error
// 	CreateUTXO(id, txID string, index int, address string, amount int64) (*chain.UTXO, error)
// 	GetUTXOsForUser(address string) ([]*chain.UTXO, error)
// 	GetUTXOs(address string) (map[string][]*chain.UTXO, error)
// 	CreateAndSignTransaction(txID string, inputs, outputs []*chain.UTXO, privKey *rsa.PrivateKey) (*chain.Transaction, error)
// 	RetrieveMLDSAPublicKey(address string) ([]byte, error)
// 	// CommitTransaction(txn *TransactionContext) error
// 	// RollbackTransaction(txn *TransactionContext) error
// 	// SetTransaction(txn *TransactionContext, key []byte, value []byte) error
// }
