package core

import (
	"bytes"
	"crypto/ed25519"
	"database/sql"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"

	"github.com/thrylos-labs/thrylos/database"
	// other necessary imports
)

// Blockchain represents the entire blockchain structure, encapsulating all blocks, stakeholders,
// and transactions within the network. It serves as the central ledger of the system, tracking
// the state of the blockchain, including ownership of assets through UTXOs (Unspent Transaction Outputs),
// and the resolution of forks, ensuring the integrity and continuity of the chain.
type Blockchain struct {
	// Blocks holds the sequence of blocks that constitute the blockchain. Each block contains
	// a set of transactions and is linked to the previous block, forming the chain.
	Blocks []*Block

	// Genesis points to the first block in the blockchain, known as the Genesis block. This block
	// is the foundation of the blockchain, with no preceding block.
	Genesis *Block

	// Adding transactions to the pending transactions pool
	PendingTransactions []*thrylos.Transaction

	// Stakeholders maps validator addresses to their respective stakes in the network. This is
	// used in proof-of-stake (PoS) consensus mechanisms to determine validators' rights to create
	// new blocks based on the size of their stake
	Stakeholders map[string]int

	// UTXOs tracks unspent transaction outputs, which represent the current state of ownership
	// of the blockchain's assets. It is a key component in preventing double spending.
	UTXOs map[string][]*thrylos.UTXO

	// Forks captures any divergences in the blockchain, where two or more blocks are found to
	// have the same predecessor. Forks are resolved through mechanisms that ensure consensus
	// on a single chain.
	Forks []*Fork

	// Mu provides concurrency control to ensure that operations on the blockchain are thread-safe,
	// preventing race conditions and ensuring data integrity.
	Mu sync.Mutex

	// lastTimestamp records the timestamp of the last added block. This is used to ensure that
	// blocks are added in chronological order, preserving the integrity of the blockchain's timeline.
	lastTimestamp int64

	// SmartContracts lists all smart contracts deployed on the blockchain. Smart contracts are
	// self-executing contracts with the terms of the agreement directly written into code
	// SmartContracts []SmartContract // New field for storing smart contracts

	// Database provides an abstraction over the underlying database technology used to persist
	// blockchain data, facilitating operations like adding blocks and retrieving blockchain state
	Database shared.BlockchainDBInterface // Updated the type to interface
}

// NewTransaction creates a new transaction
type Stakeholder struct {
	Address string
	Stake   int
}

// Fork structure representing a fork in the blockchain
type Fork struct {
	Index  int
	Blocks []*Block
}

// NewBlockchain initializes and returns a new instance of a Blockchain. It sets up the necessary
// infrastructure, including the genesis block and the database connection for persisting the blockchain state.
func NewBlockchain(dataDir string, aesKey []byte) (*Blockchain, error) {
	// Initialize the database
	db, err := database.InitializeDatabase(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize the blockchain database: %v", err)
	}
	defer func() {
		if err != nil {
			db.Close()
		}
	}()

	// Create a new BlockchainDB instance
	bdb := database.NewBlockchainDB(db, aesKey)

	// Create the genesis block
	genesis := NewGenesisBlock()

	// After genesis creation
	// Assuming you have a Serialize method on the Block type
	serializedGenesis, err := genesis.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize genesis block: %v", err)
	}

	// Insert the serialized genesis block into the database
	if err := bdb.InsertBlock(serializedGenesis, 0); err != nil {
		return nil, fmt.Errorf("failed to add genesis block to the database: %v", err)
	}

	// Add initial transactions simulating a starting state
	genesisTransactions := make([]*thrylos.Transaction, 0)

	// Simulate several stakeholders
	stakeholders := []struct {
		Address string
		Balance int64
	}{
		{"address1", 10000},
		{"address2", 20000},
		{"address3", 15000},
	}

	// Initialize Stakeholders map
	stakeholdersMap := make(map[string]int)

	// Create a genesis transaction for each stakeholder
	for _, stakeholder := range stakeholders {
		genesisTx := &thrylos.Transaction{
			Id:        "genesis_tx_" + stakeholder.Address,
			Timestamp: time.Now().Unix(),
			Outputs: []*thrylos.UTXO{{
				OwnerAddress: stakeholder.Address,
				Amount:       stakeholder.Balance,
			}},
			Signature: "genesis_signature", // Placeholder
		}
		genesisTransactions = append(genesisTransactions, genesisTx)
		stakeholdersMap[stakeholder.Address] = int(stakeholder.Balance) // Initialize stakeholder stakes
	}

	genesis.Transactions = genesisTransactions

	// Create and return the Blockchain instance
	blockchain := &Blockchain{
		Blocks:       []*Block{genesis},
		Genesis:      genesis,
		Stakeholders: stakeholdersMap,
		Database:     bdb,
		UTXOs:        make(map[string][]*thrylos.UTXO),
		Forks:        make([]*Fork, 0),
	}

	// Register genesis transaction outputs as UTXOs
	for _, tx := range genesis.Transactions {
		for idx, out := range tx.Outputs {
			utxoKey := fmt.Sprintf("%s:%d", tx.Id, idx)
			blockchain.UTXOs[utxoKey] = append(blockchain.UTXOs[utxoKey], out)
			log.Printf("UTXO added for address %s with amount %d", out.OwnerAddress, out.Amount)
		}
	}

	return blockchain, nil
}

func (bc *Blockchain) MintTokens(toAddress string, amount int) error {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	mintTx := &thrylos.Transaction{
		Id:        "mint_tx_" + toAddress,
		Timestamp: time.Now().Unix(),
		Outputs: []*thrylos.UTXO{{
			OwnerAddress: toAddress,
			Amount:       int64(amount),
		}},
		Signature: "system_signature", // System signature or a special validation
	}

	// Validate and process the transaction
	// This example skips validation since it's a system-generated transaction
	bc.AddPendingTransaction(mintTx)
	_, err := bc.ProcessPendingTransactions("system") // Assumes system or another validator processes this
	return err
}

// When reading or processing transactions that have been deserialized from Protobuf, you'll use ConvertProtoUTXOToShared to convert the Protobuf-generated UTXOs back into the format your application uses internally.

// ConvertProtoUTXOToShared converts a Protobuf-generated UTXO to your shared UTXO type.
func ConvertProtoUTXOToShared(protoUTXO *thrylos.UTXO) shared.UTXO {
	return shared.UTXO{
		ID:            protoUTXO.GetTransactionId(), // Assuming you have corresponding fields
		TransactionID: protoUTXO.GetTransactionId(),
		Index:         int(protoUTXO.GetIndex()), // Convert from int32 to int if necessary
		OwnerAddress:  protoUTXO.GetOwnerAddress(),
		Amount:        int(protoUTXO.GetAmount()), // Convert from int64 to int if necessary
	}
}

func (bc *Blockchain) Status() string {
	// Example status: return the number of blocks in the blockchain
	return fmt.Sprintf("Current blockchain length: %d blocks", len(bc.Blocks))
}

// In this updated method, you're retrieving a slice of *thrylos.UTXO from the UTXOs map using the provided address. Then, you iterate over this slice, converting each *thrylos.UTXO to shared.UTXO using the ConvertProtoUTXOToShared function, and build a slice of shared.UTXO to return.

// GetUTXOsForAddress returns all UTXOs for a given address.
func (bc *Blockchain) GetUTXOsForAddress(address string) []shared.UTXO {
	protoUTXOs := bc.UTXOs[address] // This retrieves a slice of *thrylos.UTXO
	sharedUTXOs := make([]shared.UTXO, len(protoUTXOs))

	for i, protoUTXO := range protoUTXOs {
		sharedUTXOs[i] = ConvertProtoUTXOToShared(protoUTXO)
	}

	return sharedUTXOs
}

func (bc *Blockchain) GetBalance(address string) (int, error) {
	var balance int

	// Track spent outputs to avoid counting coins that have been spent.
	spentOutputs := make(map[string]bool)

	for _, block := range bc.Blocks {
		for _, tx := range block.Transactions {
			// Check outputs first - add to the balance if this address received coins
			for i, output := range tx.Outputs {
				outputKey := fmt.Sprintf("%s:%d", tx.Id, i)
				if output.OwnerAddress == address {
					if !spentOutputs[outputKey] {
						balance += int(output.Amount)
					}
				}
			}

			// Check inputs - subtract from balance if this address spent coins and the outputs had been added to the balance
			for _, input := range tx.Inputs {
				if input.OwnerAddress == address {
					spentKey := fmt.Sprintf("%s:%d", input.TransactionId, input.Index)
					if !spentOutputs[spentKey] { // Check if this input was already marked as spent
						spentOutputs[spentKey] = true
						balance -= int(input.Amount)
					}
				}
			}
		}
	}

	return balance, nil
}

// In blockchain.go, within your Blockchain struct definition
func (bc *Blockchain) RetrievePublicKey(ownerAddress string) (ed25519.PublicKey, error) {
	log.Printf("Attempting to retrieve public key from database for address: %s", ownerAddress)
	publicKeyBytes, err := bc.Database.RetrieveEd25519PublicKey(ownerAddress)
	if err != nil {
		log.Printf("Database error retrieving public key: %v", err)
		return nil, err
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		errorMsg := fmt.Sprintf("retrieved public key size is incorrect for address: %s", ownerAddress)
		log.Printf(errorMsg)
		return nil, fmt.Errorf(errorMsg)
	}

	publicKey := ed25519.PublicKey(publicKeyBytes)
	log.Printf("Successfully retrieved and validated public key for address: %s", ownerAddress)
	return publicKey, nil
}

// CreateBlock generates a new block with the given transactions, validator, previous hash, and timestamp.
// This method encapsulates the logic for building a block to be added to the blockchain.
func (bc *Blockchain) CreateBlock(transactions []*thrylos.Transaction, validator string, prevHash string, timestamp int64) *Block {
	// Log the incoming transactions
	log.Printf("Creating block with %d transactions", len(transactions))
	for i, tx := range transactions {
		log.Printf("Transaction %d: ID=%s, Outputs=%+v", i, tx.Id, tx.Outputs)
	}

	// Create a new block with Protobuf transactions
	newBlock := &Block{
		Index:        int32(len(bc.Blocks)), // Convert len to int32
		Transactions: transactions,          // Directly use the Protobuf transactions
		Timestamp:    timestamp,
		Validator:    validator,
		PrevHash:     prevHash,
	}

	// Log the newly created block details before returning
	log.Printf("New block created: Index=%d, Hash=%s, Transactions=%d, Timestamp=%d, Validator=%s, PrevHash=%s",
		newBlock.Index, newBlock.Hash, len(newBlock.Transactions), newBlock.Timestamp, newBlock.Validator, newBlock.PrevHash)

	// Assuming ComputeHash() is adapted to work with the new Transactions type
	newBlock.Hash = newBlock.ComputeHash()

	return newBlock
}

func (bc *Blockchain) SlashMaliciousValidator(validatorAddress string, slashAmount int) {
	if _, ok := bc.Stakeholders[validatorAddress]; ok {
		// Deduct the slashAmount from the stake
		bc.Stakeholders[validatorAddress] -= slashAmount
		if bc.Stakeholders[validatorAddress] <= 0 {
			// Remove validator if their stake goes to zero or negative
			delete(bc.Stakeholders, validatorAddress)
		}
	}
}

func (bc *Blockchain) ResolveForks() {
	var longestFork *Fork
	longestLength := len(bc.Blocks)
	for _, fork := range bc.Forks {
		if len(fork.Blocks)+fork.Index > longestLength {
			longestLength = len(fork.Blocks) + fork.Index
			longestFork = fork
		}
	}
	if longestFork != nil {
		// Switch to the longest fork
		bc.Blocks = append(bc.Blocks[:longestFork.Index], longestFork.Blocks...)
	}
	// Clear forks as the longest chain is now the main chain
	bc.Forks = nil
}

// In Blockchain
func (bc *Blockchain) InsertOrUpdatePublicKey(address string, publicKey []byte, keyType string) error {
	log.Printf("InsertOrUpdatePublicKey called with address: %s, keyType: %s", address, keyType)
	log.Printf("PublicKey: %x", publicKey)

	switch keyType {
	case "Ed25519":
		return bc.Database.InsertOrUpdateEd25519PublicKey(address, publicKey)
	default:
		return fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// ValidateBlock checks if the block is valid
func (bc *Blockchain) ValidateBlock(newBlock *Block, prevBlock *Block) bool {
	// Debugging: Print the timestamps for debugging
	fmt.Printf("Validating block with timestamp: %d against previous block with timestamp: %d\n", newBlock.Timestamp, prevBlock.Timestamp)

	// Check if PrevHash matches the hash of the previous block
	if newBlock.Timestamp <= prevBlock.Timestamp {
		fmt.Printf("Invalid timestamp in block %d: should be greater than %d, got %d\n", newBlock.Index, prevBlock.Timestamp, newBlock.Timestamp)
		return false
	}

	// Validate the block's proof of stake
	if !bc.VerifyPoSRules(*newBlock) {
		fmt.Printf("Invalid block %d due to PoS rules: validator was %s\n", newBlock.Index, newBlock.Validator)
		fmt.Printf("Full block: %+v\n", newBlock)
		return false
	}

	// Validate the block's hash
	computedHash := newBlock.ComputeHash()
	if newBlock.Hash != computedHash {
		fmt.Printf("Invalid hash in block %d: expected %s, got %s\n", newBlock.Index, computedHash, newBlock.Hash)
		return false
	}

	return true
}

func (bc *Blockchain) GetLastBlock() (*Block, int, error) {
	// Query the last block data and index
	blockData, lastIndex, err := bc.Database.GetLastBlockData()
	if err != nil {
		if err == sql.ErrNoRows {
			// Handle no rows returned, which means the blockchain is empty
			return nil, 0, nil
		}
		return nil, 0, err
	}

	// Deserialize the block
	var lastBlock Block
	buffer := bytes.NewBuffer(blockData)
	decoder := gob.NewDecoder(buffer)
	err = decoder.Decode(&lastBlock)
	if err != nil {
		return nil, 0, err
	}

	// Return the block along with its index
	return &lastBlock, lastIndex, nil
}

// addUTXO adds a new UTXO to the blockchain's UTXO set.
func (bc *Blockchain) addUTXO(utxo shared.UTXO) {
	utxoKey := fmt.Sprintf("%s:%d", utxo.TransactionID, utxo.Index)
	// Ensure the UTXO list for the key is initialized
	if _, exists := bc.UTXOs[utxoKey]; !exists {
		bc.UTXOs[utxoKey] = []*thrylos.UTXO{}
	}
	// Convert shared UTXO to thrylos UTXO and add it
	thrylosUtxo := shared.ConvertSharedUTXOToProto(utxo)
	bc.UTXOs[utxoKey] = append(bc.UTXOs[utxoKey], thrylosUtxo)
	log.Printf("UTXO added: %s", utxoKey)
}

// removeUTXO removes a UTXO from the blockchain's UTXO set based on transaction ID and index.
func (bc *Blockchain) removeUTXO(transactionID string, index int32) bool {
	utxoKey := fmt.Sprintf("%s:%d", transactionID, index)
	if _, exists := bc.UTXOs[utxoKey]; exists {
		delete(bc.UTXOs, utxoKey)
		return true
	}
	return false
}

// VerifyTransaction checks the validity of a transaction against the current state of the blockchain,
// including signature verification and double spending checks. It's essential for maintaining the
// Example snippet for VerifyTransaction method adjustment
func (bc *Blockchain) VerifyTransaction(tx *thrylos.Transaction) (bool, error) {
	// Function to retrieve Ed25519 public key from the address
	getEd25519PublicKeyFunc := func(address string) (ed25519.PublicKey, error) {
		pubKey, err := bc.Database.RetrievePublicKeyFromAddress(address)
		if err != nil {
			return ed25519.PublicKey{}, err // Return the zero value for ed25519.PublicKey in case of error
		}
		return pubKey, nil
	}

	// Assuming you've made necessary adjustments to the rest of your code to handle the protobuf and shared.UTXO types correctly
	protoUTXOs := make(map[string][]*thrylos.UTXO)
	for key, utxos := range bc.UTXOs {
		protoUTXOs[key] = utxos // Adjust according to your actual type conversion if necessary
	}

	// Verify the transaction using the converted UTXOs and both public key types
	isValid, err := shared.VerifyTransaction(tx, protoUTXOs, getEd25519PublicKeyFunc)
	if err != nil {
		fmt.Printf("Error during transaction verification: %v\n", err)
		return false, err
	}
	if !isValid {
		fmt.Println("Signature verification failed or transaction is invalid")
		return false, nil
	}
	return true, nil
}

// AddPendingTransaction adds a new transaction to the pool of pending transactions.
func (bc *Blockchain) AddPendingTransaction(tx *thrylos.Transaction) {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()
	bc.PendingTransactions = append(bc.PendingTransactions, tx)
}

// ProcessPendingTransactions processes all pending transactions, attempting to form a new block.
func (bc *Blockchain) ProcessPendingTransactions(validator string) (*Block, error) {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	for _, tx := range bc.PendingTransactions {
		log.Printf("Processing transaction %s", tx.Id)
		for _, input := range tx.Inputs {
			if removed := bc.removeUTXO(input.TransactionId, input.Index); !removed {
				log.Printf("Failed to remove input UTXO: TransactionID: %s, Index: %d", input.TransactionId, input.Index)
				continue
			}
			log.Printf("Input UTXO removed: TransactionID: %s, Index: %d", input.TransactionId, input.Index)
		}
		for _, output := range tx.Outputs {
			newUTXO := shared.CreateUTXO(tx.Id, tx.Id, int(output.Index), output.OwnerAddress, int(output.Amount))
			bc.addUTXO(newUTXO)
			log.Printf("Output UTXO added: Transaction ID: %s, Owner: %s, Amount: %d", tx.Id, output.OwnerAddress, output.Amount)
		}
	}

	selectedValidator := bc.SelectValidator()
	if validator != selectedValidator {
		return nil, fmt.Errorf("selected validator does not match")
	}

	rewardTransaction := &thrylos.Transaction{
		// Implementation for reward transaction
	}
	bc.PendingTransactions = append(bc.PendingTransactions, rewardTransaction)

	newBlock := bc.CreateBlock(bc.PendingTransactions, validator, bc.Blocks[len(bc.Blocks)-1].Hash, time.Now().Unix())
	if newBlock == nil {
		return nil, fmt.Errorf("failed to create a new block")
	}

	bc.Blocks = append(bc.Blocks, newBlock)
	bc.PendingTransactions = nil
	return newBlock, nil
}

// Get the block and see how many transactions are in each block

func (bc *Blockchain) GetBlockByID(id string) (*Block, error) {
	// iterate over blocks and find by ID
	for _, block := range bc.Blocks {
		if block.Hash == id || strconv.Itoa(int(block.Index)) == id { // Convert int32 to int before converting to string
			log.Printf("Block found: Index=%d, Transactions=%v", block.Index, block.Transactions)
			return block, nil
		}
	}
	log.Println("Block not found with ID:", id)
	return nil, errors.New("block not found")
}

func (bc *Blockchain) GetTransactionByID(id string) (*thrylos.Transaction, error) {
	// iterate over blocks and transactions to find by ID
	for _, block := range bc.Blocks {
		for _, tx := range block.Transactions {
			if tx.Id == id {
				return tx, nil
			}
		}
	}
	return nil, errors.New("transaction not found")
}

func (bc *Blockchain) GetBlock(blockNumber int) (*Block, error) {
	blockData, err := bc.Database.RetrieveBlock(blockNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve block data: %v", err)
	}

	var block Block
	if err := json.Unmarshal(blockData, &block); err != nil { // Deserialize here
		return nil, fmt.Errorf("failed to deserialize block: %v", err)
	}
	return &block, nil
}

// AddBlock adds a new block to the blockchain, with an optional timestamp.
// If the timestamp is 0, the current system time is used as the block's timestamp.
func (bc *Blockchain) AddBlock(transactions []*thrylos.Transaction, validator string, prevHash string, optionalTimestamp ...int64) (bool, error) {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	var timestamp int64
	if len(optionalTimestamp) > 0 && optionalTimestamp[0] > 0 {
		timestamp = optionalTimestamp[0]
	} else {
		timestamp = time.Now().Unix()
	}

	// Handle potential forks.
	if len(bc.Blocks) > 0 && prevHash != bc.Blocks[len(bc.Blocks)-1].Hash {
		var selectedFork *Fork
		for _, fork := range bc.Forks {
			if fork.Blocks[len(fork.Blocks)-1].Hash == prevHash {
				selectedFork = fork
				break
			}
		}

		newBlock := bc.CreateBlock(transactions, validator, prevHash, timestamp)
		if newBlock == nil {
			return false, fmt.Errorf("failed to create a new block")
		}

		blockData, err := json.Marshal(newBlock) // Serialize here
		if err != nil {
			return false, fmt.Errorf("failed to serialize new block: %v", err)
		}

		blockNumber := len(bc.Blocks) // This should be after block validation
		if selectedFork != nil {
			selectedFork.Blocks = append(selectedFork.Blocks, newBlock)
			blockNumber = len(selectedFork.Blocks) - 1
		} else {
			bc.Blocks = append(bc.Blocks, newBlock)
			blockNumber = len(bc.Blocks) - 1 // Use the index of the newly appended block
		}

		if err := bc.Database.StoreBlock(blockData, blockNumber); err != nil {
			return false, fmt.Errorf("failed to store block in database: %v", err)
		}

		return true, nil
	}

	// Verify transactions.
	for _, tx := range transactions {
		isValid, err := bc.VerifyTransaction(tx) // Ensure VerifyTransaction accepts *thrylos.Transaction
		if err != nil || !isValid {
			return false, fmt.Errorf("transaction verification failed: %s, error: %v", tx.GetId(), err)
		}
	}

	// Handle UTXOs: updating UTXO set with new transactions.
	for _, tx := range transactions {
		for _, input := range tx.GetInputs() {
			utxoKey := fmt.Sprintf("%s:%d", input.GetTransactionId(), input.GetIndex())
			delete(bc.UTXOs, utxoKey)
		}
		for index, output := range tx.GetOutputs() {
			utxoKey := fmt.Sprintf("%s:%d", tx.GetId(), index)
			// Append output to the slice for this utxoKey
			bc.UTXOs[utxoKey] = append(bc.UTXOs[utxoKey], output)
		}
	}

	// Create and validate the new block.
	prevBlock := bc.Blocks[len(bc.Blocks)-1] // Ensure there is at least one block before doing this
	newBlock := bc.CreateBlock(transactions, validator, prevHash, timestamp)
	if newBlock == nil || !bc.ValidateBlock(newBlock, prevBlock) {
		return false, fmt.Errorf("failed to create or validate a new block")
	}

	// Serialize the new block for storage
	blockData, err := newBlock.Serialize()
	if err != nil {
		return false, fmt.Errorf("failed to serialize new block: %v", err)
	}

	// Use the length of the blockchain as the new block number
	blockNumber := len(bc.Blocks) // This should be calculated appropriately

	if err := bc.Database.InsertBlock(blockData, blockNumber); err != nil {
		return false, fmt.Errorf("failed to insert block into database: %v", err)
	}

	// Update the blockchain with the new block
	bc.Blocks = append(bc.Blocks, newBlock)
	bc.lastTimestamp = timestamp

	return true, nil
}

// RewardValidator rewards the validator with new tokens
func (bc *Blockchain) RewardValidator(validator string, reward int) {
	bc.Mu.Lock() // Lock
	bc.Stakeholders[validator] += reward
	bc.Mu.Unlock() // Unlock
}

// VerifyPoSRules verifies the PoS rules for the given block
func (bc *Blockchain) VerifyPoSRules(block Block) bool {
	// Check if the validator had a stake at the time of block creation
	_, exists := bc.Stakeholders[block.Validator]
	return exists
}

// CheckChainIntegrity verifies the entire blockchain for hash integrity and chronological order,
// ensuring that no blocks have been altered or inserted maliciously. It's a safeguard against tampering
// and a key component in the blockchain's security mechanisms.
func (bc *Blockchain) CheckChainIntegrity() bool {
	for i := 1; i < len(bc.Blocks); i++ {
		prevBlock := bc.Blocks[i-1]
		currentBlock := bc.Blocks[i]
		if currentBlock.PrevHash != prevBlock.Hash {
			fmt.Println("Invalid previous hash in block:", currentBlock.Index)
			return false
		}
		if currentBlock.Hash != currentBlock.ComputeHash() {
			fmt.Println("Invalid hash in block:", currentBlock.Index)
			return false
		}
	}
	return true
}
