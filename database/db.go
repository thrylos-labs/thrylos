package database

// The database package provides functionalities to interact with a relational database
// for storing and retrieving blockchain data, including blocks, transactions, public keys, and UTXOs.

import (
	"Thrylos/shared"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"

	"github.com/dgraph-io/badger"
)

// BlockchainDB wraps an SQL database connection and provides methods to interact
// with the blockchain data stored within. It supports operations like inserting or updating public keys,
// retrieving balances based on UTXOs, and adding transactions to the database.

type BlockchainDB struct {
	DB            *badger.DB
	utxos         map[string]shared.UTXO
	Blockchain    shared.BlockchainDBInterface // Use the interface here
	encryptionKey []byte                       // The AES-256 key used for encryption and decryption
}

var (
	db   *badger.DB
	once sync.Once
)

// InitializeDatabase sets up the initial database schema including tables for blocks,
// public keys, and transactions. It ensures the database is ready to store blockchain data.
// InitializeDatabase ensures that BadgerDB is only initialized once
func InitializeDatabase(dataDir string) (*badger.DB, error) {
	var err error
	once.Do(func() {
		// Use dataDir for the database directory
		opts := badger.DefaultOptions(dataDir).WithLogger(nil)
		db, err = badger.Open(opts)
	})
	return db, err
}

// NewBlockchainDB creates a new instance of BlockchainDB with the necessary initialization.
// encryptionKey should be securely provided, e.g., from environment variables or a secure vault service.
func NewBlockchainDB(db *badger.DB, encryptionKey []byte) *BlockchainDB {
	return &BlockchainDB{
		DB:            db,
		utxos:         make(map[string]shared.UTXO),
		encryptionKey: encryptionKey,
	}
}

// encryptData encrypts data using AES-256 GCM.
func (bdb *BlockchainDB) encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(bdb.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decryptData decrypts data using AES-256 GCM.
func (bdb *BlockchainDB) decryptData(encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(bdb.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(encryptedData) < gcm.NonceSize() {
		return nil, fmt.Errorf("invalid encrypted data")
	}

	nonce, ciphertext := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// InsertOrUpdatePrivateKey stores the private key in the database, encrypting it first.
// InsertOrUpdatePrivateKey stores the private key in the database, encrypting it first.
func (bdb *BlockchainDB) InsertOrUpdatePrivateKey(address string, privateKey []byte) error {

	// Log the private key bytes before base64 encoding
	log.Printf("Private key bytes before base64 encoding: %v", privateKey)

	// Base64 encode the private key first
	encodedKey := base64.StdEncoding.EncodeToString(privateKey)
	log.Printf("Base64 encoded key: %s", encodedKey)

	encryptedKey, err := bdb.encryptData([]byte(encodedKey))
	if err != nil {
		log.Printf("Error encrypting private key for address %s: %v", address, err)
		return fmt.Errorf("error encrypting private key: %v", err)
	}

	err = bdb.DB.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("privateKey-"+address), encryptedKey)
	})
	if err != nil {
		log.Printf("Error storing encrypted private key for address %s: %v", address, err)
		return fmt.Errorf("error storing encrypted private key: %v", err)
	}

	log.Printf("Successfully inserted/updated private key for address %s", address)
	return nil
}

// RetrievePrivateKey retrieves the private key for the given address, decrypting it before returning.
func (bdb *BlockchainDB) RetrievePrivateKey(address string) ([]byte, error) {
	log.Printf("Retrieving private key for address: %s", address)
	storageKey := "privateKey-" + address + "-ed25519"
	log.Printf("Looking for storage key: %s", storageKey)

	var encryptedKey []byte
	err := bdb.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(storageKey))
		if err != nil {
			log.Printf("Key not found in database: %s, error: %v", storageKey, err)
			return err
		}

		encryptedKey, err = item.ValueCopy(nil)
		if err != nil {
			log.Printf("Failed to get value for key: %s, error: %v", storageKey, err)
			return err
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve encrypted private key: %v", err)
	}

	decryptedData, err := bdb.decryptData(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %v", err)
	}
	log.Printf("Decrypted base64 string: %s", string(decryptedData))

	decodedData, err := base64.StdEncoding.DecodeString(string(decryptedData))
	if err != nil {
		log.Printf("Error decoding base64 data: %v", err)
		return nil, err
	}
	log.Printf("Decoded private key data: %v", decodedData)

	return decodedData, nil
}

// fetching of UTXOs from BadgerDB
func (bdb *BlockchainDB) GetUTXOsForAddress(address string) ([]shared.UTXO, error) {
	var utxos []shared.UTXO
	err := bdb.DB.View(func(txn *badger.Txn) error {
		prefix := []byte(fmt.Sprintf("utxo-%s-", address)) // Assuming keys are prefixed with utxo-{address}-
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return err
				}
				utxos = append(utxos, utxo)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error retrieving UTXOs for address %s: %v", address, err)
	}
	return utxos, nil
}

func (bdb *BlockchainDB) InsertOrUpdateEd25519PublicKey(address string, publicKey []byte) error {
	log.Printf("Attempting to insert public key for address: %s", address)
	data, err := json.Marshal(map[string][]byte{"ed25519PublicKey": publicKey})
	if err != nil {
		log.Printf("Failed to marshal public key: %v", err)
		return err
	}

	err = bdb.DB.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("publicKey-"+address), data)
	})
	if err != nil {
		log.Printf("Failed to insert public key for address %s: %v", address, err)
		return err
	}
	log.Printf("Successfully inserted public key for address: %s", address)
	return nil
}

type publicKeyData struct {
	Ed25519PublicKey   []byte `json:"ed25519PublicKey"`
	DilithiumPublicKey []byte `json:"dilithiumPublicKey"`
}

func (bdb *BlockchainDB) RetrieveEd25519PublicKey(address string) (ed25519.PublicKey, error) {
	log.Printf("Attempting to retrieve public key for address: %s", address)
	var publicKeyData []byte
	err := bdb.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("publicKey-" + address))
		if err != nil {
			log.Printf("Failed to find public key for address %s: %v", address, err)
			return err
		}
		return item.Value(func(val []byte) error {
			var data map[string][]byte
			if err := json.Unmarshal(val, &data); err != nil {
				return err
			}
			publicKeyData = data["ed25519PublicKey"]
			return nil
		})
	})
	if err != nil {
		log.Printf("Failed to retrieve public key for address %s: %v", address, err)
		return nil, err
	}
	if publicKeyData == nil || len(publicKeyData) == 0 {
		log.Printf("No public key found for address %s", address)
		return nil, fmt.Errorf("no Ed25519 public key found for address %s", address)
	}
	log.Printf("Successfully retrieved public key for address: %s", address)
	return ed25519.PublicKey(publicKeyData), nil
}

func (bdb *BlockchainDB) InsertOrUpdateDilithiumPublicKey(address string, dilithiumPublicKey []byte) error {
	// Implement the logic specific to Dilithium public keys.
	// This might simply involve calling InsertOrUpdatePublicKey with the correct arguments.
	return bdb.InsertOrUpdatePublicKey(address, nil, dilithiumPublicKey) // Pass nil for the Ed25519 key if you're not updating it.
}

func (bdb *BlockchainDB) RetrieveDilithiumPublicKey(address string) ([]byte, error) {
	return bdb.RetrieveDilithiumPublicKeyFromAddress(address)
}

func (bdb *BlockchainDB) InsertOrUpdatePublicKey(address string, ed25519PublicKey, dilithiumPublicKey []byte) error {
	data, err := json.Marshal(map[string][]byte{
		"ed25519PublicKey":   ed25519PublicKey,
		"dilithiumPublicKey": dilithiumPublicKey,
	})
	if err != nil {
		log.Printf("Error marshalling public key data for address %s: %v", address, err)
		return err
	}

	err = bdb.DB.Update(func(txn *badger.Txn) error {
		log.Printf("Attempting to store public key for address %s", address)
		return txn.Set([]byte("publicKey-"+address), data)
	})

	if err != nil {
		log.Printf("Error updating public key in the database for address %s: %v", address, err)
	} else {
		log.Printf("Successfully updated public key in the database for address %s", address)
	}

	return err
}

func (bdb *BlockchainDB) RetrieveDilithiumPublicKeyFromAddress(address string) ([]byte, error) {
	var dilithiumPublicKeyBytes []byte
	err := bdb.DB.View(func(txn *badger.Txn) error {
		key := []byte("publicKey-" + address)
		item, err := txn.Get(key)
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return fmt.Errorf("no Dilithium public key found for address %s", address)
			}
			return fmt.Errorf("error retrieving data from BadgerDB: %w", err)
		}

		err = item.Value(func(val []byte) error {
			var keyData map[string][]byte
			if err := json.Unmarshal(val, &keyData); err != nil {
				return fmt.Errorf("error unmarshalling data: %w", err)
			}

			var ok bool
			dilithiumPublicKeyBytes, ok = keyData["dilithiumPublicKey"]
			if !ok {
				return fmt.Errorf("no Dilithium public key found in the data for address %s", address)
			}

			return nil
		})
		return err
	})

	if err != nil {
		return nil, err
	}

	return dilithiumPublicKeyBytes, nil
}

// RetrievePublicKeyFromAddress fetches the public key for a given blockchain address from the database.
// It is essential for verifying transaction signatures and ensuring the integrity of transactions.
func (bdb *BlockchainDB) RetrievePublicKeyFromAddress(address string) (ed25519.PublicKey, error) {
	log.Printf("Attempting to retrieve public key for address: %s", address)
	var publicKeyData []byte
	err := bdb.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("publicKey-" + address))
		if err != nil {
			log.Printf("Error retrieving key from DB for address %s: %v", address, err)
			return err
		}
		return item.Value(func(val []byte) error {
			publicKeyData = append([]byte{}, val...) // Make a copy of the data
			log.Printf("Retrieved public key data for address %s", address)
			return nil
		})
	})
	if err != nil {
		log.Printf("Failed to retrieve or decode public key for address %s: %v", address, err)
		return nil, err
	}

	var keys map[string][]byte
	if err := json.Unmarshal(publicKeyData, &keys); err != nil {
		log.Printf("Error unmarshalling public key data for address %s: %v", address, err)
		return nil, err
	}

	ed25519Key, ok := keys["ed25519PublicKey"]
	if !ok || len(ed25519Key) == 0 {
		log.Printf("No Ed25519 public key found for address %s", address)
		return nil, fmt.Errorf("no Ed25519 public key found for address %s", address)
	}

	log.Printf("Successfully retrieved and parsed Ed25519 public key for address %s", address)
	return ed25519.PublicKey(ed25519Key), nil
}

// GetBalance calculates the total balance for a given address based on its UTXOs.
// This function is useful for determining the spendable balance of a blockchain account.
func (bdb *BlockchainDB) GetBalance(address string, utxos map[string]shared.UTXO) (int, error) {
	userUTXOs, err := bdb.Blockchain.GetUTXOsForUser(address, utxos)
	if err != nil {
		return 0, err
	}
	var balance int
	for _, utxo := range userUTXOs {
		balance += utxo.Amount
	}
	return balance, nil
}

// AddTransaction stores a new transaction in the database. It serializes transaction inputs,
// outputs, and the signature for persistent storage.
func (bdb *BlockchainDB) AddTransaction(tx shared.Transaction) error {
	// Serialize the entire transaction object to JSON for storage.
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("error marshaling transaction: %v", err)
	}

	// Use the transaction ID as the key for the key-value store.
	key := []byte("transaction-" + tx.ID)

	// Start a write transaction in BadgerDB.
	err = bdb.DB.Update(func(txn *badger.Txn) error {
		// Put the serialized transaction data into the BadgerDB store.
		return txn.Set(key, txJSON)
	})

	if err != nil {
		return fmt.Errorf("error storing transaction in BadgerDB: %v", err)
	}

	return nil
}

func (bdb *BlockchainDB) GetAllUTXOs() (map[string]shared.UTXO, error) {
	utxos := make(map[string]shared.UTXO)

	err := bdb.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte("utxo-")
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.ValidForPrefix(opts.Prefix); it.Next() {
			item := it.Item()
			key := item.KeyCopy(nil)

			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return fmt.Errorf("error unmarshalling UTXO: %v", err)
				}

				// Assuming the UTXO ID is part of the key, and the key format is "utxo-<utxoID>"
				utxoID := string(key)[5:]
				utxos[utxoID] = utxo

				return nil
			})
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error retrieving UTXOs: %v", err)
	}

	return utxos, nil
}

func (bdb *BlockchainDB) GetTransactionByID(txID string, recipientPrivateKey *rsa.PrivateKey) (*shared.Transaction, error) {
	var encryptedTx shared.Transaction // Use your actual transaction structure here

	err := bdb.DB.View(func(txn *badger.Txn) error {
		key := []byte("transaction-" + txID)
		item, err := txn.Get(key)
		if err != nil {
			return fmt.Errorf("error retrieving transaction: %v", err)
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &encryptedTx)
		})
	})

	if err != nil {
		return nil, err
	}

	// encryptedTx.EncryptedAESKey contains the RSA-encrypted AES key
	encryptedKey := encryptedTx.EncryptedAESKey // This field should exist in your encrypted transaction structure

	// Decrypt the encrypted inputs and outputs using the AES key
	decryptedInputsData, err := shared.DecryptTransactionData(encryptedTx.EncryptedInputs, encryptedKey, recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt inputs: %v", err)
	}

	decryptedOutputsData, err := shared.DecryptTransactionData(encryptedTx.EncryptedOutputs, encryptedKey, recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt outputs: %v", err)
	}

	// Deserialize the decrypted data into your actual data structures
	var inputs []shared.UTXO
	var outputs []shared.UTXO
	if err := json.Unmarshal(decryptedInputsData, &inputs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal inputs: %v", err)
	}
	if err := json.Unmarshal(decryptedOutputsData, &outputs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal outputs: %v", err)
	}

	// Construct the decrypted transaction object
	tx := &shared.Transaction{
		ID:        encryptedTx.ID,
		Timestamp: encryptedTx.Timestamp,
		Inputs:    inputs,
		Outputs:   outputs,
		// You can continue populating this struct with the necessary fields...
	}

	return tx, nil
}

func (bdb *BlockchainDB) GetLatestBlockData() ([]byte, error) {
	var latestBlockData []byte

	err := bdb.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true // Iterate in reverse order
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			if strings.HasPrefix(string(key), "block-") {
				// We've found the latest block
				err := item.Value(func(val []byte) error {
					// Make a copy of the block data
					latestBlockData = append([]byte(nil), val...)
					return nil
				})
				return err // Return from the View function after finding the latest block
			}
		}

		return fmt.Errorf("no blocks found in the database")
	})

	if err != nil {
		return nil, err
	}

	return latestBlockData, nil
}

func (bdb *BlockchainDB) CreateAndStoreUTXO(id, txID string, index int, owner string, amount int) error {
	utxo := shared.CreateUTXO(id, txID, index, owner, amount)

	// Marshal the UTXO object into JSON for storage.
	utxoJSON, err := json.Marshal(utxo)
	if err != nil {
		return fmt.Errorf("error marshalling UTXO: %v", err)
	}

	// Prepare the key for this UTXO entry in the database.
	key := []byte("utxo-" + id)

	// Use BadgerDB transaction to put the UTXO data into the database.
	err = bdb.DB.Update(func(txn *badger.Txn) error {
		return txn.Set(key, utxoJSON)
	})
	if err != nil {
		return fmt.Errorf("error inserting UTXO into BadgerDB: %v", err)
	}

	return nil
}

func (bdb *BlockchainDB) UpdateUTXOs(inputs []shared.UTXO, outputs []shared.UTXO) error {
	// Loop over the inputs and mark them as spent in the database
	for _, input := range inputs {
		err := bdb.MarkUTXOAsSpent(input)
		if err != nil {
			// Handle error marking UTXO as spent.
			return fmt.Errorf("error marking UTXO as spent: %w", err)
		}
	}

	// Loop over the outputs and add them as new UTXOs in the database
	for _, output := range outputs {
		err := bdb.addNewUTXO(output)
		if err != nil {
			// Handle error adding new UTXO.
			return fmt.Errorf("error adding new UTXO: %w", err)
		}
	}

	return nil
}

func (bdb *BlockchainDB) AddUTXO(utxo shared.UTXO) error {
	// Add the utxo to the database
	// This is a placeholder; replace with your actual implementation logic.
	return nil
}

// Replace with your actual implementation to mark UTXO as spent in the database
func (bdb *BlockchainDB) MarkUTXOAsSpent(utxo shared.UTXO) error {
	// TODO: implement logic to mark UTXO as spent in the database
	return nil
}

// Replace with your actual implementation to add new UTXO in the database
func (bdb *BlockchainDB) addNewUTXO(utxo shared.UTXO) error {
	// TODO: implement logic to add new UTXO in the database
	return nil
}

func (bdb *BlockchainDB) GetUTXOs() (map[string][]shared.UTXO, error) {
	utxos := make(map[string][]shared.UTXO)
	// Your logic here to populate the utxos map from your database

	return utxos, nil
}

func (bdb *BlockchainDB) InsertBlock(blockData []byte, blockNumber int) error {
	key := []byte(fmt.Sprintf("block-%d", blockNumber))

	// Use BadgerDB transaction to put the block data into the database.
	err := bdb.DB.Update(func(txn *badger.Txn) error {
		return txn.Set(key, blockData)
	})

	if err != nil {
		return fmt.Errorf("error inserting block into BadgerDB: %v", err)
	}

	return nil
}

func (bdb *BlockchainDB) GetLastBlockData() ([]byte, error) {
	var blockData []byte

	err := bdb.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true // Iterate in reverse order to get the latest block first
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()

			// Assuming block data keys are prefixed with "block-"
			if strings.HasPrefix(string(key), "block-") {
				var err error
				blockData, err = item.ValueCopy(nil) // Use ValueCopy to get the data
				if err != nil {
					return fmt.Errorf("error retrieving block data: %v", err)
				}
				return nil // Break after finding the latest block
			}
		}

		return fmt.Errorf("no blocks found in the database")
	})

	if err != nil {
		return nil, err
	}

	if len(blockData) == 0 {
		return nil, fmt.Errorf("no blocks found in the database")
	}

	return blockData, nil
}

func (bdb *BlockchainDB) CreateAndSignTransaction(txID string, inputs, outputs []shared.UTXO, privKey *rsa.PrivateKey) (shared.Transaction, error) {
	tx := shared.NewTransaction(txID, inputs, outputs)

	// Serialize the transaction without the signature
	txBytes, err := tx.SerializeWithoutSignature()
	if err != nil {
		return tx, fmt.Errorf("error serializing transaction: %v", err) // returning tx, error
	}

	// Hash the serialized transaction
	hashedTx := sha256.Sum256(txBytes)

	// Sign the hashed transaction
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedTx[:])
	if err != nil {
		return tx, fmt.Errorf("error signing transaction: %v", err) // returning tx, error
	}

	// Encode the signature to base64
	base64Signature := base64.StdEncoding.EncodeToString(signature)

	// Set the encoded signature on the transaction
	tx.Signature = base64Signature
	return tx, nil // returning tx, nil
}

func (bdb *BlockchainDB) CreateUTXO(id, txID string, index int, address string, amount int) (shared.UTXO, error) {
	// Use the existing CreateUTXO method to create a UTXO object
	utxo := shared.CreateUTXO(id, txID, index, address, amount)

	// Check if the UTXO ID already exists to avoid duplicates
	if _, exists := bdb.utxos[id]; exists {
		return shared.UTXO{}, fmt.Errorf("UTXO with ID %s already exists", id)
	}

	// Add the created UTXO to the map
	bdb.utxos[id] = utxo

	return utxo, nil
}

func (bdb *BlockchainDB) GetUTXOsForUser(address string, utxos map[string]shared.UTXO) ([]shared.UTXO, error) {
	// I am using provided utxos map as it is one of the parameters in your interface
	// If utxos should be obtained from the BlockchainDB's utxos, replace utxos with bdb.utxos
	userUTXOs := []shared.UTXO{}
	for _, utxo := range utxos {
		if utxo.OwnerAddress == address {
			userUTXOs = append(userUTXOs, utxo)
		}
	}

	return userUTXOs, nil
}
