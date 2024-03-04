package database

// The database package provides functionalities to interact with a relational database
// for storing and retrieving blockchain data, including blocks, transactions, public keys, and UTXOs.

import (
	"Thrylos/shared"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// BlockchainDB wraps an SQL database connection and provides methods to interact
// with the blockchain data stored within. It supports operations like inserting or updating public keys,
// retrieving balances based on UTXOs, and adding transactions to the database.

type BlockchainDB struct {
	DB         *sql.DB
	utxos      map[string]shared.UTXO
	Blockchain shared.BlockchainDBInterface // Use the interface here
}

// InitializeDatabase sets up the initial database schema including tables for blocks,
// public keys, and transactions. It ensures the database is ready to store blockchain data.
func InitializeDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./blockchain.db")
	if err != nil {
		return nil, fmt.Errorf("Failed to open database: %w", err)
	}

	// Existing table for blocks
	createBlocksTableSQL := `
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_data BLOB
        );`
	_, err = db.Exec(createBlocksTableSQL)
	if err != nil {
		return nil, fmt.Errorf("Error creating blocks table: %w", err)
	}
	fmt.Println("Blocks table created successfully.") // Add logging

	// New table for publicKey-to-address mappings
	createPublicKeyTableSQL := `
        CREATE TABLE IF NOT EXISTS publicKeys (
            address TEXT PRIMARY KEY,
            publicKey BLOB
        );`
	_, err = db.Exec(createPublicKeyTableSQL)
	if err != nil {
		return nil, fmt.Errorf("Error creating publicKeys table: %w", err)
	}
	fmt.Println("publicKeys table created successfully") // Add logging

	// New table for transactions
	createTransactionsTableSQL := `
        CREATE TABLE IF NOT EXISTS transactions (
            ID TEXT PRIMARY KEY,
            Inputs TEXT NOT NULL,
            Outputs TEXT NOT NULL,
            Timestamp INTEGER NOT NULL,
            Signature TEXT
        );`
	_, err = db.Exec(createTransactionsTableSQL)
	if err != nil {
		return nil, fmt.Errorf("Error creating transactions table: %w", err)
	}
	fmt.Println("Transactions table created successfully") // Add logging

	// Add Signature column to transactions table if it doesn't exist
	alterTransactionsTableSQL := `
        ALTER TABLE transactions ADD COLUMN IF NOT EXISTS Signature TEXT;`
	// Execute the ALTER TABLE statement
	// This may fail if the column already exists which is fine, so we ignore the error.
	db.Exec(alterTransactionsTableSQL)

	return db, nil
}

// InsertOrUpdatePublicKey adds a new public key to the database or updates it if it already exists.
// This function is critical for managing the association between user addresses and their public keys.
func (bdb *BlockchainDB) InsertOrUpdatePublicKey(address string, pemPublicKey []byte) error {
	// Check if an entry for the address already exists
	var exists bool
	err := bdb.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM publicKeys WHERE address = ?)", address).Scan(&exists)
	if err != nil {
		return err
	}

	if exists {
		// Update existing entry
		_, err = bdb.DB.Exec("UPDATE publicKeys SET publicKey = ? WHERE address = ?", pemPublicKey, address)
	} else {
		// Insert new entry
		_, err = bdb.DB.Exec("INSERT INTO publicKeys (address, publicKey) VALUES (?, ?)", address, pemPublicKey)
	}
	return err
}

// RetrievePublicKeyFromAddress fetches the public key for a given blockchain address from the database.
// It is essential for verifying transaction signatures and ensuring the integrity of transactions.
func (bdb *BlockchainDB) RetrievePublicKeyFromAddress(address string) (*rsa.PublicKey, error) {
	row := bdb.DB.QueryRow("SELECT publicKey FROM publicKeys WHERE address = ?", address)

	var pemData []byte
	err := row.Scan(&pemData)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no public key found for address %s", address)
		}
		return nil, err
	}

	// Log the raw PEM data for debugging
	fmt.Printf("Retrieved raw PEM data for address %s: %s\n", address, string(pemData))

	// Decode the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		// Here, you could log the specific issue or take other actions as needed.
		return nil, fmt.Errorf("failed to decode PEM block from stored public key for address %s", address)
	}

	// Parse the RSA public key from the PEM block
	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing public key for address %s: %v", address, err)
	}

	// Assert the type to *rsa.PublicKey
	pubKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key type is not RSA for address %s", address)
	}

	// Log the parsed public key for debugging
	fmt.Printf("Retrieved and parsed public key for address %s: %+v\n", address, pubKey)

	return pubKey, nil
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
	// Convert the Inputs and Outputs slices to JSON strings for storage.
	inputsJSON, err := json.Marshal(tx.Inputs)
	if err != nil {
		return fmt.Errorf("error marshaling transaction inputs: %v", err)
	}

	outputsJSON, err := json.Marshal(tx.Outputs)
	if err != nil {
		return fmt.Errorf("error marshaling transaction outputs: %v", err)
	}

	signatureJSON, err := json.Marshal(tx.Signature)
	if err != nil {
		return fmt.Errorf("error marshaling transaction signature: %v", err)
	}

	// Prepare an SQL statement to insert the transaction into the transactions table.
	stmt, err := bdb.DB.Prepare("INSERT INTO transactions (ID, Inputs, Outputs, Timestamp, Signature) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("error preparing statement: %v", err)
	}
	defer stmt.Close()

	// Execute the SQL statement with the transaction details.
	_, err = stmt.Exec(tx.ID, inputsJSON, outputsJSON, tx.Timestamp, signatureJSON)
	if err != nil {
		return fmt.Errorf("error executing statement: %v", err)
	}

	return nil
}

func (bdb *BlockchainDB) GetAllUTXOs() (map[string]shared.UTXO, error) {
	// Here, the assumption is that you have stored UTXOs in some form in a database.
	// You should query the database to fetch all UTXOs and return them as a map.

	utxos := make(map[string]shared.UTXO)

	rows, err := bdb.DB.Query("SELECT * FROM utxos") // Adjust the SQL query as per your database schema.
	if err != nil {
		return nil, fmt.Errorf("Error querying UTXOs: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var utxoID string
		var utxoData []byte

		if err := rows.Scan(&utxoID, &utxoData); err != nil {
			return nil, fmt.Errorf("Error scanning row: %v", err)
		}

		var utxo shared.UTXO
		if err := json.Unmarshal(utxoData, &utxo); err != nil {
			return nil, fmt.Errorf("Error unmarshalling UTXO: %v", err)
		}

		utxos[utxoID] = utxo
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("Rows iteration error: %v", err)
	}

	return utxos, nil
}

func (bdb *BlockchainDB) GetTransactionByID(txID string) (*shared.Transaction, error) {
	var inputsJSON, outputsJSON []byte
	var timestamp int64
	var signature string // Change this from []byte to string

	query := "SELECT Inputs, Outputs, Timestamp, Signature FROM transactions WHERE ID = ?"
	err := bdb.DB.QueryRow(query, txID).Scan(&inputsJSON, &outputsJSON, &timestamp, &signature) // Directly scan into signature as a string
	if err != nil {
		return nil, err // Handle no rows error as needed
	}

	var inputs, outputs []shared.UTXO
	if err := json.Unmarshal(inputsJSON, &inputs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(outputsJSON, &outputs); err != nil {
		return nil, err
	}

	// No need to unmarshal signature since it's already the correct type (string)

	tx := &shared.Transaction{
		ID:        txID,
		Inputs:    inputs,  // Make sure inputs are correctly unmarshaled from inputsJSON
		Outputs:   outputs, // Make sure outputs are correctly unmarshaled from outputsJSON
		Timestamp: timestamp,
		Signature: signature, // Directly assign since it's already a base64 string
	}
	return tx, nil
}

func (bdb *BlockchainDB) GetLatestBlockData() ([]byte, error) {
	var blockData []byte
	err := bdb.DB.QueryRow("SELECT block_data FROM blocks ORDER BY id DESC LIMIT 1").Scan(&blockData)
	if err != nil {
		return nil, err // Handle no rows error as needed
	}

	return blockData, nil
}

func (bdb *BlockchainDB) CreateAndStoreUTXO(id, txID string, index int, owner string, amount int) error {
	utxo := shared.CreateUTXO(id, txID, index, owner, amount)

	utxoJSON, err := json.Marshal(utxo)
	if err != nil {
		return fmt.Errorf("error marshalling UTXO: %v", err)
	}

	_, err = bdb.DB.Exec(`INSERT INTO utxos (id, data) VALUES (?, ?)`, id, utxoJSON)
	if err != nil {
		return fmt.Errorf("error inserting UTXO into the database: %v", err)
	}

	return nil
}

// func (bdb *BlockchainDB) SendTransaction(fromAddress, toAddress string, amount int, privKey *rsa.PrivateKey) (bool, error) {
// 	allUTXOs, err := bdb.GetAllUTXOs()
// 	if err != nil {
// 		return false, fmt.Errorf("failed to get all UTXOs: %v", err)
// 	}

// 	// This function needs to be adjusted or implemented to return []*thrylos.UTXO
// 	userUTXOs := shared.GetUTXOsForUser(fromAddress, allUTXOs)
// 	protoUTXOs := make([]*thrylos.UTXO, 0)
// 	for _, utxo := range userUTXOs {
// 		protoUTXO := shared.ConvertSharedUTXOToProto(utxo)
// 		protoUTXOs = append(protoUTXOs, protoUTXO)
// 	}

// 	var inputAmount int = 0
// 	var protoInputs []*thrylos.UTXO
// 	for _, utxo := range protoUTXOs {
// 		if inputAmount < amount {
// 			protoInputs = append(protoInputs, utxo)
// 			inputAmount += int(utxo.Amount)
// 		}
// 		if inputAmount >= amount {
// 			break
// 		}
// 	}

// 	if inputAmount < amount {
// 		return false, fmt.Errorf("insufficient funds")
// 	}

// 	// Outputs including change
// 	change := inputAmount - amount
// 	protoOutputs := []*thrylos.UTXO{
// 		{
// 			TransactionId: "output1",
// 			Index:         0,
// 			OwnerAddress:  toAddress,
// 			Amount:        int64(amount),
// 		},
// 	}
// 	if change > 0 {
// 		changeOutput := &thrylos.UTXO{
// 			TransactionId: "change1",
// 			Index:         1,
// 			OwnerAddress:  fromAddress,
// 			Amount:        int64(change),
// 		}
// 		protoOutputs = append(protoOutputs, changeOutput)
// 	}

// 	tx, err := shared.CreateAndSignTransactionProto("txID123", protoInputs, protoOutputs, privKey) // Adjust this to use a function that works with Protobuf types
// 	if err != nil {
// 		return false, fmt.Errorf("failed to create and sign transaction: %v", err)
// 	}

// 	getPublicKeyFunc := func(address string) (*rsa.PublicKey, error) {
// 		// Implement this function or ensure it's correctly defined elsewhere
// 		return bdb.GetPublicKey(address)
// 	}

// 	isValid, err := shared.VerifyTransaction(tx, protoUTXOs, getPublicKeyFunc) // Adjust this to accept and return Protobuf types
// 	if !isValid || err != nil {
// 		return false, fmt.Errorf("transaction verification failed: %v", err)
// 	}

// 	// Implement AddTransaction to accept *thrylos.Transaction
// 	if err := bdb.AddTransaction(tx); err != nil {
// 		return false, fmt.Errorf("failed to add transaction: %v", err)
// 	}

// 	err = bdb.UpdateUTXOs(inputs, outputs)
// 	if err != nil {
// 		return false, fmt.Errorf("Update utxo failed")
// 	}

// 	// Assuming MarkUTXOAsSpent and AddUTXO are methods on BlockchainDB or its interface
// 	for _, in := range inputs {
// 		bdb.MarkUTXOAsSpent(in) // pass the whole UTXO object
// 	}
// 	for _, out := range outputs {
// 		err := bdb.AddUTXO(out) // Assuming AddUTXO returns an error
// 		if err != nil {
// 			return false, fmt.Errorf("Add utxo failed")
// 		}
// 	}

// 	return false, fmt.Errorf("nill")
// }

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

func (bdb *BlockchainDB) InsertBlock(blockData []byte) error {
	_, err := bdb.DB.Exec("INSERT INTO blocks (block_data) VALUES (?)", blockData)
	return err
}

func (bdb *BlockchainDB) GetLastBlockData() ([]byte, error) {
	var blockData []byte
	err := bdb.DB.QueryRow("SELECT block_data FROM blocks ORDER BY id DESC LIMIT 1").Scan(&blockData)
	return blockData, err
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

// func (bdb *BlockchainDB) ValidateTransaction(tx shared.Transaction) (bool, error) {
// 	// Fetch all available UTXOs
// 	availableUTXOs, err := bdb.GetAllUTXOs()
// 	if err != nil {
// 		return false, fmt.Errorf("error fetching UTXOs: %v", err)
// 	}

// 	// Validate each transaction input
// 	for _, input := range tx.Inputs {
// 		// Assuming your UTXO has a unique ID that is a string,
// 		// check if the input refers to a valid UTXO
// 		utxo, exists := availableUTXOs[input.ID]
// 		if !exists {
// 			return false, errors.New("invalid input: referenced UTXO does not exist")
// 		}

// 		// Verify the signature using the public key of the input's owner
// 		publicKey, err := bdb.RetrievePublicKeyFromAddress(utxo.OwnerAddress)
// 		if err != nil {
// 			return false, fmt.Errorf("error retrieving public key: %v", err)
// 		}

// 		// Adjusted to handle error from VerifyTransactionSignature correctly
// 		if err := shared.VerifyTransactionSignature(&tx, publicKey); err != nil {
// 			return false, fmt.Errorf("invalid signature: %v", err)
// 		}

// 		// Here you can also check if the input amounts are correct,
// 		// and if the sum of input amounts is greater or equal to the sum of output amounts.
// 	}

// 	// Perform other necessary validations for your transaction like
// 	// checking the output amounts, etc.

// 	return true, nil
// }

// func (bdb *BlockchainDB) VerifyTransaction(tx shared.Transaction) (bool, error) {
// 	// 1. Verify the signature of the transaction
// 	if len(tx.Inputs) == 0 {
// 		return false, errors.New("Transaction has no inputs")
// 	}
// 	senderAddress := tx.Inputs[0].OwnerAddress // Assuming all inputs come from the same address

// 	// Use the database function to retrieve the public key based on the address.
// 	senderPublicKey, err := bdb.RetrievePublicKeyFromAddress(senderAddress)
// 	if err != nil {
// 		return false, fmt.Errorf("Error retrieving public key for address %s: %v", senderAddress, err)
// 	}

// 	// Adjusted to handle error from VerifyTransactionSignature correctly
// 	if err := shared.VerifyTransactionSignature(&tx, senderPublicKey); err != nil {
// 		return false, fmt.Errorf("Transaction signature verification failed: %v", err)
// 	}

// 	// Fetch all available UTXOs
// 	availableUTXOs, err := bdb.GetAllUTXOs()
// 	if err != nil {
// 		return false, fmt.Errorf("Error fetching UTXOs: %v", err)
// 	}

// 	// 2. Check the UTXOs to verify they exist and calculate the input sum
// 	inputSum := 0
// 	for _, input := range tx.Inputs {
// 		utxo, exists := availableUTXOs[input.TransactionID+strconv.Itoa(input.Index)]
// 		if !exists {
// 			return false, fmt.Errorf("Input UTXO %s not found", input.TransactionID+strconv.Itoa(input.Index))
// 		}
// 		inputSum += utxo.Amount
// 	}

// 	// 3. Calculate the output sum
// 	outputSum := 0
// 	for _, output := range tx.Outputs {
// 		outputSum += output.Amount
// 	}

// 	// 4. Verify if the input sum matches the output sum
// 	if inputSum != outputSum {
// 		return false, fmt.Errorf("Failed to validate transaction %s: Input sum (%d) does not match output sum (%d)", tx.ID, inputSum, outputSum)
// 	}

// 	return true, nil
// }
