package shared

import (
	"crypto/ed25519"
	"crypto/rsa"
)

// BlockchainDBInterface defines a set of operations for interacting with the blockchain's underlying data storage.
// This interface abstracts the database interactions, allowing for flexibility in the implementation of data persistence.
// It includes methods for managing balances, transactions, blocks, and public keys.
type BlockchainDBInterface interface {
	// GetBalance calculates and returns the balance for a given address based on its UTXOs.
	GetBalance(address string, utxos map[string]UTXO) (int, error)

	// SendTransaction creates and processes a transaction from a sender to a recipient for a specified amount.
	// It signs the transaction using the sender's private key.
	SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error)

	SanitizeAndFormatAddress(address string) (string, error)

	// // VerifyTransaction checks the validity of a transaction, including signature verification and UTXO checks.
	// VerifyTransaction(tx Transaction) (bool, error)

	// ValidateTransaction examines a transaction for correctness, ensuring that inputs match outputs
	// and that the transaction conforms to the rules of the blockchain.
	// ValidateTransaction(tx Transaction) (bool, error)

	// InsertBlock saves a new block's data to the database.
	InsertBlock(data []byte, blockNumber int) error

	// GetLastBlockData retrieves the data of the most recently added block.
	GetLastBlockData() ([]byte, error)

	// RetrievePublicKeyFromAddress fetches the public key associated with a given blockchain address.
	RetrievePublicKeyFromAddress(address string) (ed25519.PublicKey, error)

	// AddTransaction records a new transaction in the database.
	AddTransaction(tx Transaction) error

	// UpdateUTXOs updates the database to reflect the consumption and creation of UTXOs as a result of transactions.
	UpdateUTXOs(inputs []UTXO, outputs []UTXO) error

	// CreateUTXO generates a new UTXO and stores it in the database.
	CreateUTXO(id, txID string, index int, address string, amount int) (UTXO, error)

	// GetUTXOsForUser returns all UTXOs belonging to a specified address.
	GetUTXOsForUser(address string, utxos map[string]UTXO) ([]UTXO, error)

	// GetAllUTXOs fetches all UTXOs from the database, typically for processing or verification purposes.
	GetAllUTXOs() (map[string]UTXO, error)

	// GetUTXOs retrieves a map of all UTXOs managed by the blockchain. This method may overlap with GetAllUTXOs
	// and could be subject to consolidation to avoid redundancy.
	GetUTXOs() (map[string][]UTXO, error)

	// Dilithium signature
	RetrieveDilithiumPublicKeyFromAddress(address string) ([]byte, error)

	// CreateAndSignTransaction constructs a new transaction with the given inputs and outputs, and signs it
	// using the private key provided. This method encapsulates the creation and initial validation of transactions.
	CreateAndSignTransaction(txID string, inputs, outputs []UTXO, privKey *rsa.PrivateKey) (Transaction, error)

	// Methods for handling Ed25519 public keys
	InsertOrUpdateEd25519PublicKey(address string, ed25519PublicKey []byte) error
	RetrieveEd25519PublicKey(address string) (ed25519.PublicKey, error)

	RetrievePrivateKey(address string) ([]byte, error)

	InsertOrUpdatePrivateKey(address string, privateKey []byte) error

	// Methods for handling Dilithium public keys
	InsertOrUpdateDilithiumPublicKey(address string, dilithiumPublicKey []byte) error
	RetrieveDilithiumPublicKey(address string) ([]byte, error)
	// ... other methods that you need to access from core
}
