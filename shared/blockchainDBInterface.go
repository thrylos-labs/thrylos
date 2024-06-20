package shared

import (
	"crypto/ed25519"
	"crypto/rsa"
)

// BlockchainDBInterface defines a set of operations for interacting with the blockchain's underlying data storage.
// This interface abstracts the database interactions, allowing for flexibility in the implementation of data persistence.
// It includes methods for managing balances, transactions, blocks, and public keys.

type BlockchainDBInterface interface {
	GetBalance(address string, utxos map[string]UTXO) (int, error)
	SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error)
	SanitizeAndFormatAddress(address string) (string, error)
	InsertBlock(data []byte, blockNumber int) error
	GetLastBlockData() ([]byte, int, error)
	RetrievePublicKeyFromAddress(address string) (ed25519.PublicKey, error)
	AddTransaction(tx Transaction) error
	UpdateUTXOs(inputs []UTXO, outputs []UTXO) error
	CreateUTXO(id, txID string, index int, address string, amount int) (UTXO, error)
	GetUTXOsForUser(address string, utxos map[string]UTXO) ([]UTXO, error)
	GetUTXOs(address string) (map[string][]UTXO, error)
	CreateAndSignTransaction(txID string, inputs, outputs []UTXO, privKey *rsa.PrivateKey) (Transaction, error)
	InsertOrUpdateEd25519PublicKey(address string, ed25519PublicKey []byte) error
	RetrieveEd25519PublicKey(address string) (ed25519.PublicKey, error)
	RetrievePrivateKey(address string) ([]byte, error)
	InsertOrUpdatePrivateKey(address string, privateKey []byte) error
	StoreBlock(data []byte, blockNumber int) error
	RetrieveBlock(blockNumber int) ([]byte, error)
	BeginTransaction() (*TransactionContext, error)
	CommitTransaction(txn *TransactionContext) error
	RollbackTransaction(txn *TransactionContext) error
	SetTransaction(txn *TransactionContext, key []byte, value []byte) error
	GetUTXOsByAddress(address string) (map[string][]UTXO, error)
	GetAllUTXOs() (map[string][]UTXO, error)
	GetUTXOsForAddress(address string) ([]UTXO, error)
	AddUTXO(utxo UTXO) error // Add this line
}
