package core

import (
	thrylos "Thrylos"
	"Thrylos/database"
	"Thrylos/shared"
	"bytes"
	"crypto/rsa"
	"database/sql"
	"encoding/gob"
	"fmt"
	"sync"
	"time"
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
func NewBlockchain() (*Blockchain, error) {
	// Initialize the SQLite database
	db, err := sql.Open("sqlite3", "./blockchain.db")
	if err != nil {
		return nil, err
	}

	// Initialize the BlockchainDB instance
	bdb := &database.BlockchainDB{
		DB: db,
	}

	genesis := NewGenesisBlock()

	return &Blockchain{
		Blocks:       []*Block{genesis},
		Genesis:      genesis,
		Stakeholders: make(map[string]int),
		Database:     bdb,                              // Add the BlockchainDB instance to the Blockchain struct
		UTXOs:        make(map[string][]*thrylos.UTXO), // Correctly instantiate the map
		Forks:        make([]*Fork, 0),                 // Initialize if not already done.
	}, nil
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

// CreateBlock generates a new block with the given transactions, validator, previous hash, and timestamp.
// This method encapsulates the logic for building a block to be added to the blockchain.
func (bc *Blockchain) CreateBlock(transactions []*thrylos.Transaction, validator string, prevHash string, timestamp int64) *Block {
	// Create a new block with Protobuf transactions
	newBlock := &Block{
		Index:        len(bc.Blocks),
		Transactions: transactions, // Directly use the Protobuf transactions
		Timestamp:    timestamp,
		Validator:    validator,
		PrevHash:     prevHash,
	}

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
func (bc *Blockchain) InsertOrUpdatePublicKey(address string, pemPublicKey []byte) error {
	return bc.Database.InsertOrUpdatePublicKey(address, pemPublicKey)
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

func (bc *Blockchain) GetLastBlock() (*Block, error) {
	var lastBlock Block

	// Query the last block
	blockData, err := bc.Database.GetLastBlockData()
	if err != nil {
		if err == sql.ErrNoRows {
			// Handle no rows returned, which means blockchain is empty
			return nil, nil
		}
		return nil, err
	}

	// Deserialize the block
	buffer := bytes.NewBuffer(blockData)
	decoder := gob.NewDecoder(buffer)
	err = decoder.Decode(&lastBlock)
	if err != nil {
		return nil, err
	}

	return &lastBlock, nil
}

// VerifyTransaction checks the validity of a transaction against the current state of the blockchain,
// including signature verification and double spending checks. It's essential for maintaining the
// Example snippet for VerifyTransaction method adjustment
func (bc *Blockchain) VerifyTransaction(tx *thrylos.Transaction) (bool, error) {
	// Function to retrieve public key from the address
	getPublicKeyFunc := func(address string) (*rsa.PublicKey, error) {
		return bc.Database.RetrievePublicKeyFromAddress(address)
	}

	// Convert your UTXOs map to the expected Protobuf type if needed
	// This step is necessary if your bc.UTXOs is not already of the type map[string][]*thrylos.UTXO
	protoUTXOs := make(map[string][]shared.UTXO)
	for key, utxos := range bc.UTXOs {
		var sharedUtxos []shared.UTXO
		for _, protoUtxo := range utxos {
			sharedUtxo := ConvertProtoUTXOToShared(protoUtxo)
			sharedUtxos = append(sharedUtxos, sharedUtxo)
		}
		protoUTXOs[key] = sharedUtxos
	}

	// Verify the transaction using the converted UTXOs and the Protobuf transaction type
	isValid, err := shared.VerifyTransaction(tx, bc.UTXOs, getPublicKeyFunc)
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

func (bc *Blockchain) ProcessPendingTransactions(validator string) (*Block, error) {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	// Example logic to process transactions
	// This is where you would validate each transaction and potentially update UTXOs

	// Select a validator based on PoS rules (simplified here)
	selectedValidator := bc.SelectValidator()

	if validator != selectedValidator {
		return nil, fmt.Errorf("selected validator does not match")
	}

	// Assume we reward the validator with a fixed amount for simplicity
	rewardTransaction := &thrylos.Transaction{
		// Create a reward transaction for the validator
	}
	bc.PendingTransactions = append(bc.PendingTransactions, rewardTransaction)

	newBlock := bc.CreateBlock(bc.PendingTransactions, validator, bc.Blocks[len(bc.Blocks)-1].Hash, time.Now().Unix())

	// Assuming CreateBlock also handles the addition of the block to the chain
	if newBlock == nil {
		return nil, fmt.Errorf("failed to create a new block")
	}

	// Clear pending transactions after they have been added to a block
	bc.PendingTransactions = []*thrylos.Transaction{}

	return newBlock, nil
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

		if selectedFork != nil {
			selectedFork.Blocks = append(selectedFork.Blocks, newBlock)
		} else {
			bc.Forks = append(bc.Forks, &Fork{
				Index:  len(bc.Blocks),
				Blocks: []*Block{newBlock},
			})
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
	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := bc.CreateBlock(transactions, validator, prevHash, timestamp)
	if newBlock == nil || !bc.ValidateBlock(newBlock, prevBlock) {
		return false, fmt.Errorf("failed to create or validate a new block")
	}

	// Serialize and insert the new block into the database.
	blockData, err := newBlock.Serialize()
	if err != nil {
		return false, fmt.Errorf("failed to serialize new block: %v", err)
	}
	if err := bc.Database.InsertBlock(blockData); err != nil {
		return false, fmt.Errorf("failed to insert block into database: %v", err)
	}

	// Update the blockchain with the new block and timestamp.
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
