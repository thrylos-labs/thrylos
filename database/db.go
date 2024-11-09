package database

// The database package provides functionalities to interact with a relational database
// for storing and retrieving blockchain data, including blocks, transactions, public keys, and UTXOs.

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ed25519"

	"github.com/dgraph-io/badger"
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
	"golang.org/x/crypto/blake2b"
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

var globalUTXOCache *shared.UTXOCache

func init() {
	var err error
	globalUTXOCache, err = shared.NewUTXOCache(1024, 10000, 0.01) // Adjust size and parameters as needed
	if err != nil {
		panic("Failed to create UTXO cache: " + err.Error())
	}
}

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

func (bdb *BlockchainDB) SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error) {
	// Step 1: Create transaction data
	transactionData := map[string]interface{}{
		"from":   fromAddress,
		"to":     toAddress,
		"amount": amount,
	}

	// Step 2: Serialize transaction data to JSON
	jsonData, err := json.Marshal(transactionData)
	if err != nil {
		return false, fmt.Errorf("error serializing transaction data: %v", err)
	}

	// Step 3: Encrypt the transaction data
	encryptedData, err := bdb.encryptData(jsonData)
	if err != nil {
		return false, fmt.Errorf("error encrypting transaction data: %v", err)
	}

	// Step 4: Sign the encrypted data
	signature, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, bdb.hashData(encryptedData), nil)
	if err != nil {
		return false, fmt.Errorf("error signing transaction: %v", err)
	}

	// Step 5: Store the encrypted transaction and signature in the database atomically
	txn := bdb.DB.NewTransaction(true)
	defer txn.Discard()

	err = bdb.storeTransactionInTxn(txn, encryptedData, signature, fromAddress, toAddress)
	if err != nil {
		return false, fmt.Errorf("error storing transaction in the database: %v", err)
	}

	if err := txn.Commit(); err != nil {
		return false, fmt.Errorf("transaction commit failed: %v", err)
	}

	return true, nil
}

func (bdb *BlockchainDB) storeTransactionInTxn(txn *badger.Txn, encryptedData, signature []byte, fromAddress, toAddress string) error {
	err := txn.Set([]byte(fmt.Sprintf("transaction:%s:%s", fromAddress, toAddress)), encryptedData)
	if err != nil {
		return err
	}
	err = txn.Set([]byte(fmt.Sprintf("signature:%s:%s", fromAddress, toAddress)), signature)
	if err != nil {
		return err
	}
	return nil
}

func (bdb *BlockchainDB) hashData(data []byte) []byte {
	hasher, _ := blake2b.New256(nil)
	hasher.Write(data)
	return hasher.Sum(nil)
}

// AddUTXO adds a UTXO to the BadgerDB database.
func (bdb *BlockchainDB) AddUTXO(utxo shared.UTXO) error {
	return bdb.DB.Update(func(txn *badger.Txn) error {
		// Ensure we have a TransactionID
		if utxo.TransactionID == "" {
			utxo.TransactionID = fmt.Sprintf("genesis-%s", utxo.OwnerAddress)
		}

		// Retrieve the current index for the address
		idxKey := fmt.Sprintf("index-%s", utxo.OwnerAddress)
		item, err := txn.Get([]byte(idxKey))
		if err != nil && err != badger.ErrKeyNotFound {
			return err
		}
		var index int64 = 0
		if err != badger.ErrKeyNotFound {
			err = item.Value(func(val []byte) error {
				index = int64(binary.BigEndian.Uint64(val))
				return nil
			})
			if err != nil {
				return err
			}
		}

		// Increment the index for the next UTXO
		index++
		utxo.Index = int(index)
		indexBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(indexBytes, uint64(index))
		if err := txn.Set([]byte(idxKey), indexBytes); err != nil {
			return err
		}

		// Create UTXO with the new index using the same format as AddNewUTXO
		key := fmt.Sprintf("utxo-%s-%s-%d", utxo.OwnerAddress, utxo.TransactionID, utxo.Index)
		val, err := json.Marshal(utxo)
		if err != nil {
			return err
		}
		return txn.Set([]byte(key), val)
	})
}

// fetching of UTXOs from BadgerDB
// GetUTXOsForAddress fetches UTXOs for a given address.
func (bdb *BlockchainDB) GetUTXOsForAddress(address string) ([]shared.UTXO, error) {
	var utxos []shared.UTXO
	err := bdb.DB.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte(fmt.Sprintf("utxo-%s-", address))
		log.Printf("Searching for UTXOs with prefix: %s", string(prefix))

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return err
				}
				log.Printf("Found UTXO: %+v", utxo)
				if !utxo.IsSpent {
					utxos = append(utxos, utxo)
					log.Printf("Added unspent UTXO: %+v", utxo)
				} else {
					log.Printf("Skipped spent UTXO: %+v", utxo)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	log.Printf("Retrieved %d UTXOs for address %s", len(utxos), address)
	return utxos, err
}

// fetchUTXOs performs the actual fetching of UTXOs from BadgerDB.
func fetchUTXOs(txn *badger.Txn, address string, utxos *[]shared.UTXO) error {
	prefix := []byte(fmt.Sprintf("utxo-%s-", address))
	log.Printf("Searching with prefix: %s", string(prefix)) // Logging the prefix used in the search

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
			*utxos = append(*utxos, utxo)
			return nil
		})
		if err != nil {
			log.Printf("Error processing item for prefix %s: %v", string(prefix), err) // Log any processing errors
			return err
		}
	}
	return nil
}

func (bdb *BlockchainDB) RetrieveTransaction(txn *badger.Txn, transactionID string) (*shared.Transaction, error) {
	var tx shared.Transaction

	key := []byte("transaction-" + transactionID)

	item, err := txn.Get(key)
	if err != nil {
		return nil, err
	}

	err = item.Value(func(val []byte) error {
		return json.Unmarshal(val, &tx)
	})
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling transaction: %v", err)
	}

	return &tx, nil
}

func (bdb *BlockchainDB) SanitizeAndFormatAddress(address string) (string, error) {
	trimmedAddress := strings.TrimSpace(address)

	if len(trimmedAddress) == 0 {
		return "", fmt.Errorf("invalid address: empty or only whitespace")
	}

	formattedAddress := strings.ToLower(trimmedAddress)

	if !regexp.MustCompile(`^[a-z0-9]+$`).MatchString(formattedAddress) {
		return "", fmt.Errorf("invalid address: contains invalid characters")
	}

	return formattedAddress, nil
}

func (bdb *BlockchainDB) InsertOrUpdateEd25519PublicKey(address string, ed25519PublicKey []byte) error {
	log.Printf("Attempting to insert/update public key for address: %s", address)

	formattedAddress, err := bdb.SanitizeAndFormatAddress(address)
	if err != nil {
		log.Printf("Error sanitizing address %s: %v", address, err)
		return err
	}
	log.Printf("Sanitized and formatted address: %s", formattedAddress)

	// Prepare the data to be inserted or updated
	data, err := json.Marshal(map[string][]byte{"ed25519PublicKey": ed25519PublicKey})
	if err != nil {
		log.Printf("Failed to marshal public key for address %s: %v", formattedAddress, err)
		return fmt.Errorf("Failed to marshal public key: %v", err)
	}
	log.Printf("Marshalled public key data length: %d bytes", len(data))

	// Start a new transaction for the database operation
	txn := bdb.DB.NewTransaction(true)
	defer txn.Discard() // Ensure that the transaction is discarded if not committed

	log.Printf("Started new transaction for address: %s", formattedAddress)

	// Attempt to set the public key in the database
	key := []byte("publicKey-" + formattedAddress)
	if err := txn.Set(key, data); err != nil {
		log.Printf("Failed to insert public key for address %s: %v", formattedAddress, err)
		return fmt.Errorf("Failed to insert public key for address %s: %v", formattedAddress, err)
	}
	log.Printf("Public key set in transaction for address: %s", formattedAddress)

	// Commit the transaction
	if err := txn.Commit(); err != nil {
		log.Printf("Transaction commit failed for public key update for address %s: %v", formattedAddress, err)
		return fmt.Errorf("Transaction commit failed for public key update for address %s: %v", formattedAddress, err)
	}

	log.Printf("Transaction committed successfully for address: %s", formattedAddress)
	log.Printf("Public key successfully updated for address %s", formattedAddress)
	return nil
}

type publicKeyData struct {
	Ed25519PublicKey []byte `json:"ed25519PublicKey"`
}

func (bdb *BlockchainDB) RetrieveEd25519PublicKey(address string) (ed25519.PublicKey, error) {
	log.Printf("Attempting to retrieve public key for address: %s", address)

	formattedAddress, err := bdb.SanitizeAndFormatAddress(address)
	if err != nil {
		log.Printf("Error sanitizing and formatting address %s: %v", address, err)
		return nil, err
	}
	log.Printf("Formatted address: %s", formattedAddress)

	var publicKeyData []byte
	err = bdb.DB.View(func(txn *badger.Txn) error {
		key := []byte(validatorPublicKeyPrefix + formattedAddress)
		log.Printf("Attempting to retrieve data for key: %s", string(key))

		item, err := txn.Get(key)
		if err != nil {
			log.Printf("Error retrieving item from database for key %s: %v", string(key), err)
			return err
		}

		return item.Value(func(val []byte) error {
			publicKeyData = val
			log.Printf("Retrieved public key data for key %s", string(key))
			return nil
		})
	})

	if err != nil {
		log.Printf("Error in database transaction for address %s: %v", formattedAddress, err)
		return nil, err
	}

	if len(publicKeyData) != ed25519.PublicKeySize {
		log.Printf("Retrieved public key has incorrect size for address %s. Expected %d, got %d",
			formattedAddress, ed25519.PublicKeySize, len(publicKeyData))
		return nil, fmt.Errorf("invalid public key size")
	}

	log.Printf("Successfully retrieved public key for address %s", formattedAddress)
	return ed25519.PublicKey(publicKeyData), nil
}

func (bdb *BlockchainDB) GetAllValidatorPublicKeys() (map[string]ed25519.PublicKey, error) {
	log.Println("Retrieving all validator public keys")

	publicKeys := make(map[string]ed25519.PublicKey)

	err := bdb.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte(validatorPublicKeyPrefix)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.Key()

			err := item.Value(func(val []byte) error {
				if len(val) != ed25519.PublicKeySize {
					return fmt.Errorf("invalid public key size for key %s", string(key))
				}

				address := string(key[len(prefix):]) // Remove prefix to get address
				publicKeys[address] = ed25519.PublicKey(val)
				return nil
			})

			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Error retrieving all validator public keys: %v", err)
		return nil, err
	}

	log.Printf("Successfully retrieved %d validator public keys", len(publicKeys))
	return publicKeys, nil
}

// Encryption helper function
func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

// Decryption helper function
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (bdb *BlockchainDB) RetrieveValidatorPublicKey(validatorAddress string) ([]byte, error) {
	var publicKey []byte
	err := bdb.DB.View(func(txn *badger.Txn) error {
		key := []byte("validatorPubKey-" + validatorAddress)
		log.Printf("Retrieving public key for validator: %s, key: %s", validatorAddress, key)
		item, err := txn.Get(key)
		if err != nil {
			log.Printf("Error retrieving public key for validator %s: %v", validatorAddress, err)
			return err
		}
		publicKey, err = item.ValueCopy(nil)
		return err
	})

	if err != nil {
		if err == badger.ErrKeyNotFound {
			log.Printf("Public key not found for validator %s", validatorAddress)
			return nil, fmt.Errorf("public key not found for validator %s", validatorAddress)
		}
		log.Printf("Error retrieving public key for validator %s: %v", validatorAddress, err)
		return nil, fmt.Errorf("error retrieving public key for validator %s: %v", validatorAddress, err)
	}

	log.Printf("Retrieved public key for validator %s: %x", validatorAddress, publicKey)
	return publicKey, nil
}

const validatorPublicKeyPrefix = "validatorPubKey-"

func (bdb *BlockchainDB) StoreValidatorPublicKey(validatorAddress string, publicKey []byte) error {
	if !strings.HasPrefix(validatorAddress, "tl1") {
		log.Printf("Invalid address format for validator %s: must start with 'tl1'", validatorAddress)
		return fmt.Errorf("invalid address format: must start with 'tl1'")
	}

	return bdb.DB.Update(func(txn *badger.Txn) error {
		key := []byte("validatorPubKey-" + validatorAddress)
		log.Printf("Storing public key for validator: %s, key: %s", validatorAddress, key)
		err := txn.Set(key, publicKey)
		if err != nil {
			log.Printf("Failed to store public key for validator %s: %v", validatorAddress, err)
			return fmt.Errorf("failed to store public key: %v", err)
		}
		log.Printf("Stored public key for validator: %s", validatorAddress)
		return nil
	})
}

func (bdb *BlockchainDB) InsertOrUpdatePublicKey(address string, ed25519PublicKey []byte) error {
	data, err := json.Marshal(map[string][]byte{
		"ed25519PublicKey": ed25519PublicKey,
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

var publicKeyCache = sync.Map{}

func (bdb *BlockchainDB) GetPublicKeyWithCaching(address string) (ed25519.PublicKey, error) {
	if key, found := publicKeyCache.Load(address); found {
		log.Printf("Public key retrieved from cache for address: %s", address)
		return key.(ed25519.PublicKey), nil
	}

	key, err := bdb.RetrievePublicKeyFromAddress(address)
	if err != nil {
		return nil, err
	}

	publicKeyCache.Store(address, key) // Cache the retrieved key
	return key, nil
}

// RetrievePublicKeyFromAddress fetches the public key for a given blockchain address from the database.
// It is essential for verifying transaction signatures and ensuring the integrity of transactions.
func (bdb *BlockchainDB) RetrievePublicKeyFromAddress(address string) (ed25519.PublicKey, error) {
	log.Printf("Attempting to retrieve public key for address: %s", address)
	var publicKeyData []byte
	err := bdb.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("publicKey-" + address))
		if err != nil {
			if err == badger.ErrKeyNotFound {
				log.Printf("Public key not found in database for address %s", address)
				return err
			}
			log.Printf("Database error on retrieving public key for address %s: %v", address, err)
			return err
		}
		return item.Value(func(val []byte) error {
			publicKeyData = append([]byte{}, val...) // Ensure you're copying the data correctly
			return nil
		})
	})

	if err != nil {
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

// PublicKeyExists checks if a public key already exists for the given address.
func (bdb *BlockchainDB) PublicKeyExists(address string) (bool, error) {
	formattedAddress, err := bdb.SanitizeAndFormatAddress(address)
	if err != nil {
		return false, fmt.Errorf("error sanitizing address: %v", err)
	}

	exists := false
	err = bdb.DB.View(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte("publicKey-" + formattedAddress))
		if err == badger.ErrKeyNotFound {
			// Key not found, publicKey does not exist
			return nil
		} else if err != nil {
			// An error occurred while trying to find the key
			return err
		}
		// Key found, publicKey exists
		exists = true
		return nil
	})

	if err != nil {
		return false, fmt.Errorf("failed to check public key existence: %v", err)
	}

	return exists, nil
}

func (bdb *BlockchainDB) TransactionExists(txn *shared.TransactionContext, txID string) (bool, error) {
	if txn == nil || txn.Txn == nil {
		return false, fmt.Errorf("invalid transaction context")
	}

	key := []byte("transaction-" + txID)
	_, err := txn.Txn.Get(key)
	if err == badger.ErrKeyNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("error checking transaction existence: %v", err)
	}
	return true, nil
}

// GetBalance calculates the total balance for a given address based on its UTXOs.
// This function is useful for determining the spendable balance of a blockchain account.
func (bdb *BlockchainDB) GetBalance(address string, utxos map[string][]shared.UTXO) (int64, error) {
	var balance int64
	userUTXOs, ok := utxos[address]
	if !ok {
		log.Printf("No UTXOs found for address: %s", address)
		return 0, nil
	}

	log.Printf("Processing UTXOs for address %s:", address)
	for i, utxo := range userUTXOs {
		utxoKey := generateUTXOKey(address, utxo.TransactionID, utxo.Index)
		if !utxo.IsSpent {
			balance += utxo.Amount
			log.Printf("UTXO %d [%s]: Amount=%d nanoTHRYLOS (%.7f THRYLOS) IsSpent=%v",
				i, utxoKey, utxo.Amount, float64(utxo.Amount)/1e7, utxo.IsSpent)
		} else {
			log.Printf("Skipping spent UTXO %d [%s]: Amount=%d IsSpent=%v",
				i, utxoKey, utxo.Amount, utxo.IsSpent)
		}
	}

	log.Printf("Final balance for %s: %d nanoTHRYLOS (%.7f THRYLOS)",
		address, balance, float64(balance)/1e7)
	return balance, nil
}

func (db *BlockchainDB) BeginTransaction() (*shared.TransactionContext, error) {
	txn := db.DB.NewTransaction(true)
	return shared.NewTransactionContext(txn), nil
}

func (db *BlockchainDB) CommitTransaction(txn *shared.TransactionContext) error {
	return txn.Txn.Commit()
}

func (db *BlockchainDB) RollbackTransaction(txn *shared.TransactionContext) error {
	txn.Txn.Discard()
	return nil
}

func (db *BlockchainDB) SetTransaction(txn *shared.TransactionContext, key []byte, value []byte) error {
	if txn == nil || txn.Txn == nil {
		return fmt.Errorf("invalid transaction context")
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	return txn.Txn.Set(key, value)
}

// AddTransaction stores a new transaction in the database. It serializes transaction inputs,
// outputs, and the signature for persistent storage.
func (bdb *BlockchainDB) AddTransaction(tx *thrylos.Transaction) error {
	txn := bdb.DB.NewTransaction(true)
	defer txn.Discard()

	txJSON, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("error marshaling transaction: %v", err)
	}

	key := []byte("transaction-" + tx.Id)

	if err := txn.Set(key, txJSON); err != nil {
		return fmt.Errorf("error storing transaction in BadgerDB: %v", err)
	}

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("transaction commit failed: %v", err)
	}

	return nil
}

func (bdb *BlockchainDB) GetUTXOsByAddress(address string) (map[string][]shared.UTXO, error) {
	utxos := make(map[string][]shared.UTXO)

	err := bdb.DB.View(func(txn *badger.Txn) error {
		prefix := []byte("utxo-" + address + "-") // Assuming keys are prefixed with utxo-<address>-
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return fmt.Errorf("error unmarshalling UTXO: %v", err)
				}

				// Extract the UTXO index from the key, format is "utxo-<address>-<index>"
				keyParts := strings.Split(string(item.Key()), "-")
				if len(keyParts) >= 3 {
					index := keyParts[2]
					utxos[index] = append(utxos[index], utxo)
				}

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

func (bdb *BlockchainDB) GetAllUTXOs() (map[string][]shared.UTXO, error) {
	allUTXOs := make(map[string][]shared.UTXO)
	err := bdb.DB.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte("utxo-")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return err
				}
				if !utxo.IsSpent {
					allUTXOs[utxo.OwnerAddress] = append(allUTXOs[utxo.OwnerAddress], utxo)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return allUTXOs, err
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

func (bdb *BlockchainDB) ProcessTransaction(tx *shared.Transaction) error {
	return bdb.DB.Update(func(txn *badger.Txn) error {
		if err := bdb.updateUTXOsInTxn(txn, tx.Inputs, tx.Outputs); err != nil {
			return err
		}
		if err := bdb.addTransactionInTxn(txn, tx); err != nil {
			return err
		}
		return nil
	})
}

func (bdb *BlockchainDB) updateUTXOsInTxn(txn *badger.Txn, inputs, outputs []shared.UTXO) error {
	for _, input := range inputs {
		key := []byte(fmt.Sprintf("utxo-%s-%d", input.TransactionID, input.Index))
		input.IsSpent = true
		utxoData, err := json.Marshal(input)
		if err != nil {
			return err
		}
		if err := txn.Set(key, utxoData); err != nil {
			return err
		}
		globalUTXOCache.Remove(fmt.Sprintf("%s-%d", input.TransactionID, input.Index))
	}

	for _, output := range outputs {
		key := []byte(fmt.Sprintf("utxo-%s-%d", output.TransactionID, output.Index))
		utxoData, err := json.Marshal(output)
		if err != nil {
			return err
		}
		if err := txn.Set(key, utxoData); err != nil {
			return err
		}
		globalUTXOCache.Add(fmt.Sprintf("%s-%d", output.TransactionID, output.Index), &output)
	}

	return nil
}

func (bdb *BlockchainDB) addTransactionInTxn(txn *badger.Txn, tx *shared.Transaction) error {
	key := []byte("transaction-" + tx.ID)
	value, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	return txn.Set(key, value)
}

func (bdb *BlockchainDB) CreateAndStoreUTXO(id, txID string, index int, owner string, amount int64) error {
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

// UpdateUTXOs updates the UTXOs in the database, marking the inputs as spent and adding new outputs.
func (bdb *BlockchainDB) UpdateUTXOs(inputs []shared.UTXO, outputs []shared.UTXO) error {
	badgerTxn := bdb.DB.NewTransaction(true)
	defer badgerTxn.Discard()

	// Create a TransactionContext wrapper
	txn := &shared.TransactionContext{Txn: badgerTxn}

	for _, input := range inputs {
		err := bdb.MarkUTXOAsSpent(txn, input)
		if err != nil {
			return fmt.Errorf("error marking UTXO as spent: %w", err)
		}
	}

	for _, output := range outputs {
		err := bdb.AddNewUTXO(txn, output)
		if err != nil {
			return fmt.Errorf("error adding new UTXO: %w", err)
		}
	}

	return badgerTxn.Commit()
}

// MarkUTXOAsSpent marks a UTXO as spent in the database.
func generateUTXOKey(address string, transactionID string, index int) string {
	if transactionID == "" {
		// For genesis or initial UTXOs, use a special format
		return fmt.Sprintf("utxo-%s-%d", address, index)
	}
	return fmt.Sprintf("utxo-%s-%s-%d", address, transactionID, index)
}

func (bdb *BlockchainDB) MarkUTXOAsSpent(txContext *shared.TransactionContext, utxo shared.UTXO) error {
	// Ensure we have all required fields
	if utxo.OwnerAddress == "" {
		return fmt.Errorf("owner address is required")
	}
	if utxo.TransactionID == "" {
		return fmt.Errorf("transaction ID is required")
	}

	// Construct the key using the transaction ID from the input
	key := fmt.Sprintf("utxo-%s-%s-%d", utxo.OwnerAddress, utxo.TransactionID, utxo.Index)
	log.Printf("Marking UTXO as spent - Key: %s, TransactionID: %s, Amount: %d, Owner: %s",
		key, utxo.TransactionID, utxo.Amount, utxo.OwnerAddress)

	// Get the existing UTXO
	item, err := txContext.Txn.Get([]byte(key))
	if err != nil {
		if err == badger.ErrKeyNotFound {
			return fmt.Errorf("UTXO not found: %s", key)
		}
		return fmt.Errorf("error retrieving UTXO: %v", err)
	}

	var existingUTXO shared.UTXO
	err = item.Value(func(val []byte) error {
		return json.Unmarshal(val, &existingUTXO)
	})
	if err != nil {
		return fmt.Errorf("error unmarshaling UTXO: %v", err)
	}

	// Verify this UTXO isn't already spent
	if existingUTXO.IsSpent {
		return fmt.Errorf("UTXO is already spent: %s", key)
	}

	// Mark as spent
	existingUTXO.IsSpent = true

	// Save back
	updatedValue, err := json.Marshal(existingUTXO)
	if err != nil {
		return fmt.Errorf("error marshaling updated UTXO: %v", err)
	}

	err = txContext.Txn.Set([]byte(key), updatedValue)
	if err != nil {
		return fmt.Errorf("error saving updated UTXO: %v", err)
	}

	log.Printf("Successfully marked UTXO as spent - Key: %s", key)
	return nil
}

func (bdb *BlockchainDB) AddNewUTXO(txContext *shared.TransactionContext, utxo shared.UTXO) error {
	// Ensure TransactionID is set
	if utxo.TransactionID == "" {
		return fmt.Errorf("cannot add UTXO without TransactionID")
	}

	key := fmt.Sprintf("utxo-%s-%s-%d", utxo.OwnerAddress, utxo.TransactionID, utxo.Index)
	val, err := json.Marshal(utxo)
	if err != nil {
		return fmt.Errorf("failed to marshal UTXO: %v", err)
	}

	return txContext.Txn.Set([]byte(key), val)
}

func GenerateUTXOKey(ownerAddress string, transactionID string, index int) string {
	return fmt.Sprintf("utxo-%s-%s-%d", ownerAddress, transactionID, index)
}

// GetUTXOs retrieves all UTXOs for a specific address.
func (bdb *BlockchainDB) GetUTXOs(address string) (map[string][]shared.UTXO, error) {
	utxos := make(map[string][]shared.UTXO)
	err := bdb.DB.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte("utxo-" + address)
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return err
				}
				if !utxo.IsSpent {
					utxos[address] = append(utxos[address], utxo)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return utxos, err
}

func (bdb *BlockchainDB) InsertBlock(blockData []byte, blockNumber int) error {
	key := fmt.Sprintf("block-%d", blockNumber)
	log.Printf("Inserting block %d into database", blockNumber)

	err := bdb.DB.Update(func(txn *badger.Txn) error {
		log.Printf("Storing data at key: %s", key)
		return txn.Set([]byte(key), blockData)
	})

	if err != nil {
		log.Printf("Error inserting block %d: %v", blockNumber, err)
		return fmt.Errorf("error inserting block into BadgerDB: %v", err)
	}

	log.Printf("Block %d inserted successfully", blockNumber)
	return nil
}

// Bech32AddressExists checks if a given Bech32 address is already registered in the database.
func (bdb *BlockchainDB) Bech32AddressExists(bech32Address string) (bool, error) {
	exists := false

	err := bdb.DB.View(func(txn *badger.Txn) error {
		// Assuming that the key for Bech32 addresses is stored as 'address-tl1<actual_address>'
		key := []byte("address-" + bech32Address) // Adjust if your key format is different

		_, err := txn.Get(key)

		if err == badger.ErrKeyNotFound {
			// Key not found, address does not exist
			return nil
		} else if err != nil {
			// An error occurred that isn't related to key non-existence
			return err
		}

		// If we get here, it means the key was found and thus the address exists
		exists = true
		return nil
	})

	return exists, err
}

// StoreBlock stores serialized block data.
func (bdb *BlockchainDB) StoreBlock(blockData []byte, blockNumber int) error {
	key := fmt.Sprintf("block-%d", blockNumber)
	log.Printf("Storing block %d in the database", blockNumber)

	return bdb.DB.Update(func(txn *badger.Txn) error {
		log.Printf("Storing data at key: %s", key)
		return txn.Set([]byte(key), blockData)
	})
}

// RetrieveBlock retrieves serialized block data by block number.
func (bdb *BlockchainDB) RetrieveBlock(blockNumber int) ([]byte, error) {
	key := fmt.Sprintf("block-%d", blockNumber)
	log.Printf("Retrieving block %d from the database", blockNumber)
	var blockData []byte

	err := bdb.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		blockData, err = item.ValueCopy(nil)
		if err != nil {
			log.Printf("Error retrieving block data from key %s: %v", key, err)
		}
		return err
	})

	if err != nil {
		log.Printf("Failed to retrieve block %d: %v", blockNumber, err)
		return nil, fmt.Errorf("failed to retrieve block data: %v", err)
	}
	log.Printf("Block %d retrieved successfully", blockNumber)
	return blockData, nil
}

func (bdb *BlockchainDB) GetLastBlockData() ([]byte, int, error) {
	var blockData []byte
	var lastIndex int = -1

	err := bdb.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			if strings.HasPrefix(string(key), "block-") {
				blockNumberStr := strings.TrimPrefix(string(key), "block-")
				var parseErr error
				lastIndex, parseErr = strconv.Atoi(blockNumberStr)
				if parseErr != nil {
					return fmt.Errorf("error parsing block number: %v", parseErr)
				}
				blockData, parseErr = item.ValueCopy(nil)
				if parseErr != nil {
					return fmt.Errorf("error retrieving block data: %v", parseErr)
				}
				return nil
			}
		}
		return fmt.Errorf("no blocks found in the database")
	})

	if err != nil {
		return nil, -1, err
	}

	if lastIndex == -1 {
		return nil, -1, fmt.Errorf("no blocks found in the database")
	}

	return blockData, lastIndex, nil
}

func (bdb *BlockchainDB) GetLastBlockIndex() (int, error) {
	var lastIndex int = -1 // Default to -1 to indicate no blocks if none found

	err := bdb.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true // Iterate in reverse order to get the latest block first
		it := txn.NewIterator(opts)
		defer it.Close()

		if it.Rewind(); it.Valid() {
			item := it.Item()
			key := item.Key()
			if strings.HasPrefix(string(key), "block-") {
				blockNumberStr := strings.TrimPrefix(string(key), "block-")
				var parseErr error
				lastIndex, parseErr = strconv.Atoi(blockNumberStr)
				if parseErr != nil {
					log.Printf("Error parsing block number from key %s: %v", key, parseErr)
					return parseErr
				}
				return nil // Stop after the first (latest) block
			}
		}
		return fmt.Errorf("no blocks found in the database")
	})

	if err != nil {
		log.Printf("Failed to retrieve the last block index: %v", err)
		return -1, err // Return -1 when no block is found
	}

	return lastIndex, nil
}

func (bdb *BlockchainDB) CreateAndSignTransaction(txID string, inputs, outputs []shared.UTXO, privKey *rsa.PrivateKey) (shared.Transaction, error) {
	tx := shared.NewTransaction(txID, inputs, outputs)

	// Serialize the transaction without the signature
	txBytes, err := tx.SerializeWithoutSignature()
	if err != nil {
		return tx, fmt.Errorf("error serializing transaction: %v", err) // returning tx, error
	}

	// Hash the serialized transaction using BLAKE2b
	hasher, _ := blake2b.New256(nil)
	hasher.Write(txBytes)
	hashedTx := hasher.Sum(nil)

	// Sign the hashed transaction
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashedTx[:])
	if err != nil {
		return tx, fmt.Errorf("error signing transaction: %v", err) // returning tx, error
	}

	// Encode the signature to base64
	base64Signature := base64.StdEncoding.EncodeToString(signature)

	// Set the encoded signature on the transaction
	tx.Signature = base64Signature // Assign the base64 string directly
	return tx, nil                 // returning tx, nil
}

func (bdb *BlockchainDB) CreateUTXO(id, txID string, index int, address string, amount int64) (shared.UTXO, error) {
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

func (bdb *BlockchainDB) GetUTXOsForUser(address string) ([]shared.UTXO, error) {
	userUTXOs := []shared.UTXO{}
	err := bdb.DB.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		prefix := []byte("utxo-" + address + "-")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var utxo shared.UTXO
				if err := json.Unmarshal(val, &utxo); err != nil {
					return err
				}
				if !utxo.IsSpent {
					userUTXOs = append(userUTXOs, utxo)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return userUTXOs, err
}
