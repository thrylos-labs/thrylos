package shared

import (
	"crypto/rsa"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/crypto/mldsa44"
)

type Store interface {
	GetUTXO(addr address.Address) ([]*UTXO, error)
	GetTransaction(id string) (*Transaction, error)
	GetLastBlock() (*Block, error)
	GetLastBlockNumber() (int, error)
	GetBlock(blockNumber uint32) (*Block, error)
	GetPublicKey(addr address.Address) (crypto.PublicKey, error)
	// GetValidator(addr address.Address) (*Validator, error)
	RetrieveValidatorPublicKey(validatorAddress string) ([]byte, error)
	BeginTransaction() (*TransactionContext, error)
	RollbackTransaction(txn *TransactionContext) error
	MarkUTXOAsSpent(txContext *TransactionContext, utxo UTXO) error
	SaveTransaction(tx *Transaction) error
	SaveBlock(blk *Block) error
	// UpdateValidator(v *Validator) error
	AddNewUTXO(txContext *TransactionContext, utxo UTXO) error
	CommitTransaction(txn *TransactionContext) error
	GetUTXOsForAddress(address string) ([]UTXO, error)
	SetTransaction(txn *TransactionContext, key []byte, value []byte) error
	AddTransaction(tx *thrylos.Transaction) error
	SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error)
	CreateAndStoreUTXO(id, txID string, index int, owner string, amount float64) error
	CreateUTXO(id, txID string, index int, address string, amount float64) (UTXO, error)
	GetUTXOsForUser(address string) ([]UTXO, error)
	UpdateUTXOs(inputs []UTXO, outputs []UTXO) error
	AddUTXO(utxo UTXO) error
	GetUTXOs(address string) (map[string][]UTXO, error)
	GetAllUTXOs() (map[string][]UTXO, error)
	GetUTXOsByAddress(address string) (map[string][]UTXO, error)
	ProcessTransaction(tx *Transaction) error

	CreateAndSignTransaction(txID string, inputs, outputs []UTXO, privKey *rsa.PrivateKey) (*Transaction, error)

	TransactionExists(txn *TransactionContext, txID string) (bool, error)
	RetrievePublicKeyFromAddress(address string) (*mldsa44.PublicKey, error)

	InsertBlock(blockData []byte, blockNumber int) error

	GetLatestBlockData() ([]byte, error)

	GetLastBlockIndex() (int, error)
	StoreBlock(blockData []byte, blockNumber int) error

	RetrieveBlock(blockNumber int) ([]byte, error)

	GetLastBlockData() ([]byte, int, error)
	GetPublicKeyWithCaching(address string) (*mldsa44.PublicKey, error)
	PublicKeyExists(address string) (bool, error)
	InsertOrUpdateMLDSAPublicKey(address string, mldsaPublicKey *mldsa44.PublicKey) error

	RetrieveMLDSAPublicKey(address string) ([]byte, error)

	GetAllValidatorPublicKeys() (map[string]mldsa44.PublicKey, error)
	StoreValidatorPublicKey(validatorAddress string, publicKeyBytes []byte) error

	StoreValidatorMLDSAPublicKey(validatorAddress string, publicKey *mldsa44.PublicKey) error
	GetValidatorMLDSAPublicKey(validatorAddress string) (*mldsa44.PublicKey, error)

	Bech32AddressExists(bech32Address string) (bool, error)
	GetBalance(address string, utxos map[string][]UTXO) (amount.Amount, error)
	SanitizeAndFormatAddress(address string) (string, error)
}
