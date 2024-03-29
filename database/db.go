package database

// The database package provides functionalities to interact with a relational database
// for storing and retrieving blockchain data, including blocks, transactions, public keys, and UTXOs.

import (
	"Thrylos/shared"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/linxGnu/grocksdb"
)

// BlockchainDB wraps an SQL database connection and provides methods to interact
// with the blockchain data stored within. It supports operations like inserting or updating public keys,
// retrieving balances based on UTXOs, and adding transactions to the database.

type BlockchainDB struct {
	DB         *grocksdb.DB
	utxos      map[string]shared.UTXO
	Blockchain shared.BlockchainDBInterface // Use the interface here
}

// InitializeDatabase sets up the initial database schema including tables for blocks,
// public keys, and transactions. It ensures the database is ready to store blockchain data.
func InitializeDatabase() (*grocksdb.DB, []*grocksdb.ColumnFamilyHandle, error) {
	opts := grocksdb.NewDefaultOptions()
	opts.SetCreateIfMissing(true)

	// In RocksDB, the "default" column family is created automatically if no other
	// column family is specified. So we need to open the database with column family.
	cfNames := []string{"default"}
	cfOpts := []*grocksdb.Options{grocksdb.NewDefaultOptions()}
	opts.SetCreateIfMissingColumnFamilies(true)

	db, cfHandles, err := grocksdb.OpenDbColumnFamilies(opts, "./blockchain.db", cfNames, cfOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open RocksDB database: %w", err)
	}

	return db, cfHandles, nil
}

func (bdb *BlockchainDB) InsertOrUpdateEd25519PublicKey(address string, ed25519PublicKey []byte) error {
	// Implement the logic specific to Ed25519 public keys.
	// This might simply involve calling InsertOrUpdatePublicKey with the correct arguments.
	return bdb.InsertOrUpdatePublicKey(address, ed25519PublicKey, nil) // Pass nil for the Dilithium key if you're not updating it.
}

func (bdb *BlockchainDB) RetrieveEd25519PublicKey(address string) (ed25519.PublicKey, error) {
	publicKeyBytes, err := bdb.RetrievePublicKeyFromAddress(address)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(publicKeyBytes), nil
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
	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()

	data, err := json.Marshal(map[string][]byte{
		"ed25519PublicKey":   ed25519PublicKey,
		"dilithiumPublicKey": dilithiumPublicKey,
	})
	if err != nil {
		return err
	}

	return bdb.DB.Put(wo, []byte("publicKey-"+address), data)
}

func (bdb *BlockchainDB) RetrieveDilithiumPublicKeyFromAddress(address string) ([]byte, error) {
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	key := []byte("publicKey-" + address)
	data, err := bdb.DB.Get(ro, key)
	if err != nil {
		return nil, fmt.Errorf("error retrieving data from RocksDB: %w", err)
	}
	defer data.Free()

	if data.Size() == 0 {
		return nil, fmt.Errorf("no Dilithium public key found for address %s", address)
	}

	var keyData map[string][]byte
	if err := json.Unmarshal(data.Data(), &keyData); err != nil {
		return nil, fmt.Errorf("error unmarshalling data: %w", err)
	}

	dilithiumPublicKeyBytes, ok := keyData["dilithiumPublicKey"]
	if !ok {
		return nil, fmt.Errorf("no Dilithium public key found in the data for address %s", address)
	}

	return dilithiumPublicKeyBytes, nil
}

// RetrievePublicKeyFromAddress fetches the public key for a given blockchain address from the database.
// It is essential for verifying transaction signatures and ensuring the integrity of transactions.
func (bdb *BlockchainDB) RetrievePublicKeyFromAddress(address string) (ed25519.PublicKey, error) {
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	data, err := bdb.DB.Get(ro, []byte("publicKey-"+address))
	if err != nil {
		return nil, err
	}
	defer data.Free()

	var keyData map[string][]byte
	if err := json.Unmarshal(data.Data(), &keyData); err != nil {
		return nil, err
	}

	return ed25519.PublicKey(keyData["ed25519PublicKey"]), nil
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

	// Write options for the RocksDB put operation.
	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()

	// Put the serialized transaction data into the RocksDB store.
	err = bdb.DB.Put(wo, key, txJSON)
	if err != nil {
		return fmt.Errorf("error storing transaction in RocksDB: %v", err)
	}

	return nil
}

func (bdb *BlockchainDB) GetAllUTXOs() (map[string]shared.UTXO, error) {
	utxos := make(map[string]shared.UTXO)

	// Create an iterator for the database.
	ro := grocksdb.NewDefaultReadOptions()
	it := bdb.DB.NewIterator(ro)

	for it.Seek([]byte("utxo-")); it.ValidForPrefix([]byte("utxo-")); it.Next() {
		key := it.Key()
		value := it.Value()

		var utxo shared.UTXO
		if err := json.Unmarshal(value.Data(), &utxo); err != nil {
			key.Free()
			value.Free()
			ro.Destroy()
			it.Close()
			return nil, fmt.Errorf("error unmarshalling UTXO: %v", err)
		}

		// Assuming the UTXO ID is part of the key, and the key format is "utxo-<utxoID>"
		utxoID := string(key.Data())[5:]
		utxos[utxoID] = utxo

		key.Free()
		value.Free()
	}

	if err := it.Err(); err != nil {
		ro.Destroy()
		it.Close()
		return nil, fmt.Errorf("iterator error: %v", err)
	}

	ro.Destroy()
	it.Close()

	return utxos, nil
}

func (bdb *BlockchainDB) GetTransactionByID(txID string) (*shared.Transaction, error) {
	// Create a read option for the database.
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	// Construct the key with which the transaction is stored.
	key := []byte("transaction-" + txID)

	// Get the transaction data from the database.
	data, err := bdb.DB.Get(ro, key)
	if err != nil {
		return nil, fmt.Errorf("error retrieving transaction from RocksDB: %w", err)
	}
	defer data.Free()

	// Check if data was found
	if data.Size() == 0 {
		return nil, fmt.Errorf("no transaction found with ID %s", txID)
	}

	// Unmarshal the transaction data into the Transaction struct.
	var tx shared.Transaction
	if err := json.Unmarshal(data.Data(), &tx); err != nil {
		return nil, fmt.Errorf("error unmarshalling transaction data: %w", err)
	}

	return &tx, nil
}

func (bdb *BlockchainDB) GetLatestBlockData() ([]byte, error) {
	// Create a read option for the database.
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	// Create an iterator for the database, set to reverse order to get the latest block first.
	it := bdb.DB.NewIterator(ro)
	defer it.Close()

	// Seek to the last key in the range of blocks and move in reverse order.
	for it.SeekToLast(); it.Valid(); it.Prev() {
		key := it.Key()
		if strings.HasPrefix(string(key.Data()), "block-") {
			// We've found the latest block
			blockData := make([]byte, len(it.Value().Data()))
			copy(blockData, it.Value().Data())

			key.Free()
			it.Value().Free()

			return blockData, nil
		}
		key.Free()
		it.Value().Free()
	}

	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterator error: %v", err)
	}

	return nil, fmt.Errorf("no blocks found in the database")
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

	// Write options for the RocksDB put operation.
	wo := grocksdb.NewDefaultWriteOptions()

	// Put the UTXO data into RocksDB.
	err = bdb.DB.Put(wo, key, utxoJSON)
	if err != nil {
		wo.Destroy() // Explicitly destroy write options when there is an error
		return fmt.Errorf("error inserting UTXO into RocksDB: %v", err)
	}

	wo.Destroy() // Explicitly destroy write options after operation is done
	return nil
}

func (bdb *BlockchainDB) GetPublicKey(address string) (*rsa.PublicKey, error) {
	// Your implementation here to get public key by address
	// This is just a placeholder
	return nil, nil
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

	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()

	err := bdb.DB.Put(wo, key, blockData)
	if err != nil {
		return fmt.Errorf("error inserting block into RocksDB: %v", err)
	}

	return nil
}

func (bdb *BlockchainDB) GetLastBlockData() ([]byte, error) {
	ro := grocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	it := bdb.DB.NewIterator(ro)
	defer it.Close()

	// Iterate in reverse order to find the latest block
	it.SeekToLast()
	if it.Valid() {
		blockData := make([]byte, len(it.Value().Data()))
		copy(blockData, it.Value().Data())

		return blockData, nil
	}

	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("error iterating blocks in RocksDB: %v", err)
	}

	return nil, fmt.Errorf("no blocks found in the database")
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
