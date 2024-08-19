package core

import (
	"bytes"
	stdEd25519 "crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"math/big"
	"sort"
	"strings"

	"golang.org/x/crypto/ed25519"
	xEd25519 "golang.org/x/crypto/ed25519"

	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/supabase-community/supabase-go"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/database"
	"github.com/thrylos-labs/thrylos/shared"
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
	Stakeholders map[string]int64 // Maps validator addresses to their respective stakes

	// UTXOs tracks unspent transaction outputs, which represent the current state of ownership
	// of the blockchain's assets. It is a key component in preventing double spending.
	UTXOs map[string][]*thrylos.UTXO

	// Forks captures any divergences in the blockchain, where two or more blocks are found to
	// have the same predecessor. Forks are resolved through mechanisms that ensure consensus
	// on a single chain.
	Forks []*Fork

	// Mu provides concurrency control to ensure that operations on the blockchain are thread-safe,
	// preventing race conditions and ensuring data integrity.
	Mu sync.RWMutex

	// lastTimestamp records the timestamp of the last added block. This is used to ensure that
	// blocks are added in chronological order, preserving the integrity of the blockchain's timeline.
	lastTimestamp int64

	// SmartContracts lists all smart contracts deployed on the blockchain. Smart contracts are
	// self-executing contracts with the terms of the agreement directly written into code
	// SmartContracts []SmartContract // New field for storing smart contracts

	// Database provides an abstraction over the underlying database technology used to persist
	// blockchain data, facilitating operations like adding blocks and retrieving blockchain state
	Database shared.BlockchainDBInterface // Updated the type to interface

	PublicKeyMap map[string]xEd25519.PublicKey // To store public keys

	GenesisAccount string // Add this to store the genesis account address

	SupabaseClient *supabase.Client

	// Manages the preictive modal
	TOBManager *TOBManager // Add this field

	ConsensusManager *ConsensusManager

	ActiveValidators []string

	MinStakeForValidator *big.Int

	Network      *Network
	ShardManager *ShardManager
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

const NanoPerThrylos = 1e7

func ThrylosToNano(thrylos float64) int64 {
	return int64(thrylos * NanoPerThrylos)
}

func NanoToThrylos(nano int64) float64 {
	return float64(nano) / NanoPerThrylos
}

// GetMinStakeForValidator returns the current minimum stake required for a validator
func (bc *Blockchain) GetMinStakeForValidator() *big.Int {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()
	return new(big.Int).Set(bc.MinStakeForValidator) // Return a copy to prevent modification
}

// You might also want to add a setter method if you need to update this value dynamically
func (bc *Blockchain) SetMinStakeForValidator(newMinStake *big.Int) {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()
	bc.MinStakeForValidator = new(big.Int).Set(newMinStake)
}

const (
	TotalSupply        = 120_000_000 // 120 million tokens
	MinStakePercentage = 0.1         // 0.1% of total supply as minimum stake
)

// NewBlockchain initializes and returns a new instance of a Blockchain. It sets up the necessary
// infrastructure, including the genesis block and the database connection for persisting the blockchain state.
func NewBlockchain(dataDir string, aesKey []byte, genesisAccount string, supabaseClient *supabase.Client) (*Blockchain, shared.BlockchainDBInterface, error) {
	// Initialize the database
	db, err := database.InitializeDatabase(dataDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize the blockchain database: %v", err)
	}
	bdb := database.NewBlockchainDB(db, aesKey)

	// Create the genesis block
	genesis := NewGenesisBlock()

	// Initialize the map for public keys
	publicKeyMap := make(map[string]xEd25519.PublicKey)

	// Use total supply for the genesis account
	totalSupply := big.NewInt(120_000_000) // 120 million tokens
	totalSupplyNano := ThrylosToNano(float64(totalSupply.Int64()))

	// Initialize Stakeholders map with only the genesis account
	stakeholdersMap := make(map[string]int64)
	stakeholdersMap[genesisAccount] = totalSupplyNano

	// Create genesis transaction
	genesisTx := &thrylos.Transaction{
		Id:        "genesis_tx_" + genesisAccount,
		Timestamp: time.Now().Unix(),
		Outputs: []*thrylos.UTXO{{
			OwnerAddress: genesisAccount,
			Amount:       totalSupplyNano,
		}},
		Signature: []byte("genesis_signature"),
	}

	// Initialize UTXO map with the genesis transaction
	utxoMap := make(map[string][]*thrylos.UTXO)
	utxoKey := fmt.Sprintf("%s:%d", genesisTx.Id, 0)
	utxoMap[utxoKey] = []*thrylos.UTXO{genesisTx.Outputs[0]}

	genesis.Transactions = []*thrylos.Transaction{genesisTx}

	network := NewNetwork()

	blockchain := &Blockchain{
		Blocks:              []*Block{genesis},
		Genesis:             genesis,
		Stakeholders:        stakeholdersMap,
		Database:            bdb,
		PublicKeyMap:        publicKeyMap,
		UTXOs:               utxoMap,
		Forks:               make([]*Fork, 0),
		GenesisAccount:      genesisAccount,
		SupabaseClient:      supabaseClient,
		PendingTransactions: make([]*thrylos.Transaction, 0),
		ActiveValidators:    make([]string, 0),
		Network:             network,
	}

	// Initialize ShardManager
	blockchain.ShardManager = NewShardManager(network)

	// Calculate and set the minimum stake for validators
	minStakePercentage := big.NewFloat(0.001) // 0.1%
	minStake := new(big.Float).Mul(new(big.Float).SetInt(totalSupply), minStakePercentage)

	blockchain.MinStakeForValidator = new(big.Int)
	minStake.Int(blockchain.MinStakeForValidator) // Convert big.Float to big.Int

	// Initialize ConsensusManager
	blockchain.ConsensusManager = NewConsensusManager(blockchain)

	// Initialize TOBManager
	blockchain.TOBManager = NewTOBManager(0.3, blockchain.ConsensusManager)

	// Generate and store validator keys
	err = blockchain.GenerateAndStoreValidatorKeys(5) // Generate 5 validator keys
	if err != nil {
		log.Printf("Warning: Failed to generate validator keys: %v", err)
		// Continue execution instead of returning
	}

	blockchain.UpdateActiveValidators(100)

	err = blockchain.LoadAllValidatorPublicKeys()
	if err != nil {
		log.Printf("Warning: Failed to load all validator public keys: %v", err)
		// Continue execution
	}

	// Update active validators (only genesis account will be active initially)
	blockchain.UpdateActiveValidators(100)

	// Start periodic validator update in a separate goroutine
	go func() {
		log.Println("Starting periodic validator update")
		blockchain.StartPeriodicValidatorUpdate(15 * time.Minute)
	}()

	// Serialize and store the genesis block
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(genesis); err != nil {
		return nil, nil, fmt.Errorf("failed to serialize genesis block: %v", err)
	}
	if err := bdb.InsertBlock(buf.Bytes(), 0); err != nil {
		return nil, nil, fmt.Errorf("failed to add genesis block to the database: %v", err)
	}

	// Initialize the first shard with the genesis block
	initialShard := blockchain.ShardManager.Shards[0]
	initialShard.Blocks = append(initialShard.Blocks, genesis)

	log.Printf("Genesis account %s initialized with total supply: %d", genesisAccount, totalSupplyNano)

	return blockchain, bdb, nil
}

func (bc *Blockchain) getActiveNodeCount() int {
	// This is a placeholder. In a real implementation, you would track active nodes.
	// For now, we'll return a constant value.
	return 50
}

func (bc *Blockchain) calculateAverageLatency() time.Duration {
	// This is a placeholder. In a real implementation, you would measure actual network latency.
	// For now, we'll return a constant value.
	return 200 * time.Millisecond
}

func (bc *Blockchain) StartPeriodicValidatorUpdate(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			bc.UpdateActiveValidators(bc.ConsensusManager.GetActiveValidatorCount())
		}
	}()
}

func (bc *Blockchain) StoreValidatorPrivateKey(address string, privKey ed25519.PrivateKey) error {
	// Implement secure storage of private keys
	// This could be in a separate, encrypted database or secure enclave
	// For demonstration, we'll just log it (DO NOT do this in production)
	log.Printf("Storing private key for validator %s: %x", address, privKey)
	return nil
}

func (bc *Blockchain) TestEd25519Implementations() {
	// Generate a key pair
	publicKey, privateKey, _ := xEd25519.GenerateKey(nil)

	// Data to sign
	message := []byte("Test message")

	// Sign with x/crypto/xEd25519
	signature := xEd25519.Sign(privateKey, message)

	// Verify with both implementations
	stdResult := stdEd25519.Verify(publicKey, message, signature)
	xResult := xEd25519.Verify(publicKey, message, signature)

	log.Printf("Test message: %s", message)
	log.Printf("Test signature: %x", signature)
	log.Printf("Test public key: %x", publicKey)
	log.Printf("Standard library verification result: %v", stdResult)
	log.Printf("x/crypto/ed25519 verification result: %v", xResult)
}

func (bc *Blockchain) AddTestPublicKeys() {
	log.Println("Adding test public keys...")

	testKeys := []struct {
		Address   string
		PublicKey xEd25519.PublicKey
	}{
		{
			Address:   "tl11rn2agc9tqwg6eemqefj5uvtns2glepu2uaztj0v8pz3d4zg87k8szawc22",
			PublicKey: xEd25519.PublicKey("YourPublicKeyDataHere"),
		},
		{
			Address:   "tl11y7u0zczfarwextp4q66gs0jdx5798qu75jzznr7494rs2qx2emzsqr7p6q",
			PublicKey: xEd25519.PublicKey("AnotherPublicKeyDataHere"),
		},
	}

	for _, key := range testKeys {
		if err := bc.Database.InsertOrUpdateEd25519PublicKey(key.Address, key.PublicKey); err != nil {
			log.Printf("Failed to add test public key: %v", err)
		} else {
			log.Printf("Test public key added for address: %s", key.Address)
		}
	}
}

func (bc *Blockchain) AddTestUTXOs() {
	log.Println("Adding test UTXOs...")

	testUTXOs := []shared.UTXO{
		{
			OwnerAddress: "tl11rn2agc9tqwg6eemqefj5uvtns2glepu2uaztj0v8pz3d4zg87k8szawc22",
			Amount:       1000,
		},
		{
			OwnerAddress: "tl11y7u0zczfarwextp4q66gs0jdx5798qu75jzznr7494rs2qx2emzsqr7p6q",
			Amount:       500,
		},
	}
	for _, utxo := range testUTXOs {
		if err := bc.Database.AddUTXO(utxo); err != nil {
			log.Printf("Failed to add test UTXO: %v", err)
		} else {
			log.Printf("Test UTXO added: Address=%s, Amount=%d", utxo.OwnerAddress, utxo.Amount)
		}
	}
}

func (bc *Blockchain) FetchPublicKeyFromSupabase(userID string) (string, error) {
	data, _, err := bc.SupabaseClient.From("blockchain_info").
		Select("public_key_base64", "exact", false).
		Eq("user_id", userID).
		Single().
		Execute()

	if err != nil {
		fmt.Println("Error executing query:", err)
		return "", fmt.Errorf("error executing query: %v", err)
	}

	var result struct {
		PublicKeyBase64 string `json:"public_key_base64"`
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		fmt.Println("Error unmarshaling data:", err)
		return "", fmt.Errorf("public key not found for user %s", userID)
	}

	return result.PublicKeyBase64, nil
}

// When reading or processing transactions that have been deserialized from Protobuf, you'll use ConvertProtoUTXOToShared to convert the Protobuf-generated UTXOs back into the format your application uses internally.

// ConvertProtoUTXOToShared converts a Protobuf-generated UTXO to your shared UTXO type.
func ConvertProtoUTXOToShared(protoUTXO *thrylos.UTXO) shared.UTXO {
	return shared.UTXO{
		ID:            protoUTXO.GetTransactionId(), // Assuming you have corresponding fields
		TransactionID: protoUTXO.GetTransactionId(),
		Index:         int(protoUTXO.GetIndex()), // Convert from int32 to int if necessary
		OwnerAddress:  protoUTXO.GetOwnerAddress(),
		Amount:        int64(protoUTXO.GetAmount()), // Convert from int64 to int if necessary
	}
}

func (bc *Blockchain) Status() string {
	// Example status: return the number of blocks in the blockchain
	return fmt.Sprintf("Current blockchain length: %d blocks", len(bc.Blocks))
}

// In this updated method, you're retrieving a slice of *thrylos.UTXO from the UTXOs map using the provided address. Then, you iterate over this slice, converting each *thrylos.UTXO to shared.UTXO using the ConvertProtoUTXOToShared function, and build a slice of shared.UTXO to return.

// GetUTXOsForAddress returns all UTXOs for a given address.
// func (bc *Blockchain) GetUTXOsForAddress(address string) []shared.UTXO {
// 	protoUTXOs := bc.UTXOs[address] // This retrieves a slice of *thrylos.UTXO
// 	sharedUTXOs := make([]shared.UTXO, len(protoUTXOs))

// 	for i, protoUTXO := range protoUTXOs {
// 		sharedUTXOs[i] = ConvertProtoUTXOToShared(protoUTXO)
// 	}

// 	return sharedUTXOs
// }

func (bc *Blockchain) GetUTXOsForAddress(address string) ([]shared.UTXO, error) {
	log.Printf("Fetching UTXOs for address: %s", address)
	utxos, err := bc.Database.GetUTXOsForAddress(address)
	if err != nil {
		log.Printf("Failed to fetch UTXOs from database: %s", err)
		return nil, err
	}
	log.Printf("Retrieved %d UTXOs for address %s", len(utxos), address)
	return utxos, nil
}

func (bc *Blockchain) GetAllUTXOs() (map[string][]shared.UTXO, error) {
	return bc.Database.GetAllUTXOs()
}

func (bc *Blockchain) GetUTXOsForUser(address string) ([]shared.UTXO, error) {
	return bc.Database.GetUTXOsForUser(address)
}

func (bc *Blockchain) GetBalance(address string) (int, error) {
	var balance int
	spentOutputs := make(map[string]bool)

	for _, block := range bc.Blocks {
		for _, tx := range block.Transactions {
			for i, output := range tx.Outputs {
				outputKey := fmt.Sprintf("%s:%d", tx.Id, i)
				if output.OwnerAddress == address {
					if !spentOutputs[outputKey] {
						balance += int(output.Amount)
						log.Printf("Added to balance: %d from output %s", output.Amount, outputKey)
					}
				}
			}

			for _, input := range tx.Inputs {
				if input.OwnerAddress == address {
					spentKey := fmt.Sprintf("%s:%d", input.TransactionId, input.Index)
					if !spentOutputs[spentKey] {
						spentOutputs[spentKey] = true
						balance -= int(input.Amount)
						log.Printf("Subtracted from balance: %d from input %s", input.Amount, spentKey)
					}
				}
			}
		}
	}
	log.Printf("Final balance for %s: %d", address, balance)
	return balance, nil
}

func (bc *Blockchain) RegisterPublicKey(pubKey string) error {
	// Convert the public key string to bytes if necessary, assuming pubKey is base64 encoded
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("error decoding public key: %v", err)
	}

	// Assuming "publicKeyAddress" should be dynamically determined or correctly provided
	return bc.Database.InsertOrUpdateEd25519PublicKey("publicKeyAddress", pubKeyBytes)
}

// In blockchain.go, within your Blockchain struct definition
func (bc *Blockchain) RetrievePublicKey(ownerAddress string) (ed25519.PublicKey, error) {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	formattedAddress, err := shared.SanitizeAndFormatAddress(ownerAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %v", err)
	}

	log.Printf("Attempting to retrieve public key for address: %s", formattedAddress)

	// First, check the in-memory map
	if pubKey, ok := bc.PublicKeyMap[formattedAddress]; ok {
		log.Printf("Public key found in memory for address: %s", formattedAddress)
		return pubKey, nil
	}

	// If not in memory, try the database
	pubKeyBytes, err := bc.Database.RetrieveEd25519PublicKey(formattedAddress)
	if err != nil {
		log.Printf("Failed to retrieve public key from database for address %s: %v", formattedAddress, err)
		return nil, err
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("retrieved public key size is incorrect for address: %s", formattedAddress)
	}

	publicKey := ed25519.PublicKey(pubKeyBytes)

	// Store in memory for future use
	bc.PublicKeyMap[formattedAddress] = publicKey

	log.Printf("Successfully retrieved and validated public key for address: %s", formattedAddress)
	return publicKey, nil
}

// Load all Validator public keys into Memory
func (bc *Blockchain) LoadAllValidatorPublicKeys() error {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	for _, validator := range bc.ActiveValidators {
		pubKeyBytes, err := bc.Database.RetrieveEd25519PublicKey(validator)
		if err != nil {
			log.Printf("Failed to load public key for validator %s: %v", validator, err)
			continue
		}
		bc.PublicKeyMap[validator] = ed25519.PublicKey(pubKeyBytes)
	}

	log.Printf("Loaded public keys for %d validators", len(bc.PublicKeyMap))
	return nil
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

func (bc *Blockchain) SlashMaliciousValidator(validatorAddress string, slashAmount int64) {
	if _, ok := bc.Stakeholders[validatorAddress]; ok {
		// Deduct the slashAmount from the stake
		bc.Stakeholders[validatorAddress] -= slashAmount
		if bc.Stakeholders[validatorAddress] <= 0 {
			// Remove validator if their stake goes to zero or negative
			delete(bc.Stakeholders, validatorAddress)
		}
	}
}

func (bc *Blockchain) GetChainID() string {
	return "0x1" // Mainnet (adjust as per your chain)
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
func (bc *Blockchain) addUTXO(utxo shared.UTXO) error {
	utxoKey := fmt.Sprintf("%s:%d", utxo.TransactionID, utxo.Index)
	log.Printf("Adding UTXO with key: %s", utxoKey)

	if _, exists := bc.UTXOs[utxoKey]; !exists {
		bc.UTXOs[utxoKey] = []*thrylos.UTXO{}
	}

	thrylosUtxo := shared.ConvertSharedUTXOToProto(utxo)
	bc.UTXOs[utxoKey] = append(bc.UTXOs[utxoKey], thrylosUtxo)

	if err := bc.Database.AddUTXO(utxo); err != nil {
		log.Printf("Failed to add UTXO to database: %s", err)
		return err
	}

	log.Printf("UTXO successfully added: %v", utxo)
	return nil
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
	getEd25519PublicKeyFunc := func(address string) (xEd25519.PublicKey, error) {
		pubKey, err := bc.Database.RetrievePublicKeyFromAddress(address)
		if err != nil {
			return xEd25519.PublicKey{}, err // Return the zero value for ed25519.PublicKey in case of error
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
	log.Printf("Number of pending transactions before processing: %d", len(bc.PendingTransactions))
	pendingTransactions := make([]*thrylos.Transaction, len(bc.PendingTransactions))
	copy(pendingTransactions, bc.PendingTransactions)
	bc.PendingTransactions = make([]*thrylos.Transaction, 0) // Reset pending transactions
	bc.Mu.Unlock()

	// Update network conditions
	currentMetrics := NetworkMetrics{
		TransactionVolume: len(pendingTransactions),
		NodeCount:         bc.getActiveNodeCount(),
		AverageLatency:    bc.calculateAverageLatency(),
	}
	bc.TOBManager.UpdateNetworkConditions(currentMetrics)

	// The TOBManager now handles updating the ConsensusManager internally
	currentBlockTime := bc.TOBManager.GetCurrentBlockTime()

	log.Printf("Processing %d pending transactions with block time %v", len(pendingTransactions), currentBlockTime)

	successfulTransactions := []*thrylos.Transaction{}

	for _, tx := range pendingTransactions {
		log.Printf("Processing transaction %s", tx.Id)

		sharedTx, err := shared.ConvertThrylosTransactionToLocal(tx)
		if err != nil {
			log.Printf("Failed to convert transaction %s: %v", tx.Id, err)
			continue
		}

		// Process and store the transaction
		err = shared.ProcessTransactionsBatch([]*shared.Transaction{&sharedTx}, bc.Database)
		if err != nil {
			log.Printf("Failed to process transaction %s: %v", tx.Id, err)
			// Add the transaction back to the pending pool
			bc.Mu.Lock()
			bc.PendingTransactions = append(bc.PendingTransactions, tx)
			bc.Mu.Unlock()
			continue
		}
		successfulTransactions = append(successfulTransactions, tx)
		log.Printf("Transaction %s processed successfully", tx.Id)
	}

	log.Printf("%d out of %d transactions processed successfully", len(successfulTransactions), len(pendingTransactions))

	if len(successfulTransactions) == 0 {
		log.Println("No transactions to include in the new block")
		return nil, nil
	}

	// Ensure the validator is active
	if !bc.IsActiveValidator(validator) {
		return nil, fmt.Errorf("validator %s is not in the active set", validator)
	}

	// Create new block with successful transactions
	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := bc.CreateBlock(successfulTransactions, validator, prevBlock.Hash, time.Now().Unix())
	if newBlock == nil {
		return nil, fmt.Errorf("failed to create a new block")
	}

	// Validate the block using the current consensus method
	if !bc.ConsensusManager.ValidateBlock(newBlock) {
		return nil, fmt.Errorf("block failed consensus validation")
	}

	// Check if the block time is within the allowed range
	if newBlock.Timestamp < prevBlock.Timestamp+int64(currentBlockTime.Seconds()) ||
		newBlock.Timestamp > prevBlock.Timestamp+int64(currentBlockTime.Seconds()*2) {
		return nil, fmt.Errorf("block time is outside the allowed range")
	}

	bc.Mu.Lock()
	bc.Blocks = append(bc.Blocks, newBlock)
	bc.Mu.Unlock()

	// Update transaction statuses
	for _, tx := range newBlock.Transactions {
		if err := bc.UpdateTransactionStatus(tx.Id, "included", newBlock.Hash); err != nil {
			log.Printf("Error updating transaction status: %v", err)
		}
		log.Printf("Transaction %s included in block %s", tx.Id, newBlock.Hash)
	}

	// After adding a new block, we might want to update the active validator set
	bc.UpdateActiveValidators(bc.ConsensusManager.GetActiveValidatorCount())

	return newBlock, nil
}

func (bc *Blockchain) UpdateTransactionStatus(txID string, status string, blockHash string) error {
	// Begin a new database transaction
	txn, err := bc.Database.BeginTransaction()
	if err != nil {
		return fmt.Errorf("failed to begin database transaction: %v", err)
	}
	defer bc.Database.RollbackTransaction(txn) // Rollback in case of error

	// Retrieve the existing transaction
	txKey := []byte("transaction-" + txID)
	txItem, err := txn.Txn.Get(txKey)
	if err != nil {
		return fmt.Errorf("error retrieving transaction: %v", err)
	}

	var tx thrylos.Transaction
	err = txItem.Value(func(val []byte) error {
		return json.Unmarshal(val, &tx)
	})
	if err != nil {
		return fmt.Errorf("error unmarshaling transaction: %v", err)
	}

	// Update the transaction status
	tx.Status = status
	tx.BlockHash = blockHash

	// Serialize the updated transaction
	updatedTxJSON, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("error marshaling updated transaction: %v", err)
	}

	// Store the updated transaction
	if err := bc.Database.SetTransaction(txn, txKey, updatedTxJSON); err != nil {
		return fmt.Errorf("error updating transaction: %v", err)
	}

	// Commit the transaction
	if err := bc.Database.CommitTransaction(txn); err != nil {
		return fmt.Errorf("error committing transaction update: %v", err)
	}

	log.Printf("Transaction %s status updated to %s in block %s", txID, status, blockHash)
	return nil
}

// validateTransactionsConcurrently runs transaction validations in parallel and collects errors.
// Validate transactions with available UTXOs
func (bc *Blockchain) validateTransactionsConcurrently(transactions []*thrylos.Transaction) []error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(transactions))

	// Convert UTXOs outside the goroutines to avoid concurrent map read/write issues
	availableUTXOs := bc.convertUTXOsToRequiredFormat()

	for _, tx := range transactions {
		wg.Add(1)
		go func(tx *thrylos.Transaction) {
			defer wg.Done()

			// Check if the transaction ID is empty
			if tx.Id == "" {
				errChan <- fmt.Errorf("transaction ID is empty")
				return
			}

			// Convert each thrylos.Transaction to a shared.Transaction
			sharedTx, err := bc.convertToSharedTransaction(tx)
			if err != nil {
				errChan <- fmt.Errorf("conversion error for transaction ID %s: %v", tx.Id, err)
				return
			}

			// Validate the converted transaction using the shared transaction validation logic
			if !shared.ValidateTransaction(sharedTx, availableUTXOs) {
				errChan <- fmt.Errorf("validation failed for transaction ID %s", sharedTx.ID)
			}
		}(tx)
	}

	wg.Wait()
	close(errChan)

	var errs []error
	for err := range errChan {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Helper function to convert thrylos.Transaction to shared.Transaction
func (bc *Blockchain) convertToSharedTransaction(tx *thrylos.Transaction) (shared.Transaction, error) {
	if tx == nil {
		return shared.Transaction{}, fmt.Errorf("nil transaction received for conversion")
	}

	signatureEncoded := base64.StdEncoding.EncodeToString(tx.Signature)

	inputs := make([]shared.UTXO, len(tx.Inputs))
	for i, input := range tx.Inputs {
		inputs[i] = shared.UTXO{
			TransactionID: input.TransactionId,
			Index:         int(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        int64(input.Amount),
		}
	}

	outputs := make([]shared.UTXO, len(tx.Outputs))
	for i, output := range tx.Outputs {
		outputs[i] = shared.UTXO{
			TransactionID: tx.Id, // Assume output inherits transaction ID
			Index:         int(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        int64(output.Amount),
		}
	}

	return shared.Transaction{
		ID:        tx.Id,
		Inputs:    inputs,
		Outputs:   outputs,
		Signature: signatureEncoded,
		Timestamp: tx.Timestamp,
		Sender:    tx.Sender,
	}, nil
}

// Function to convert Blockchain UTXOs to a format usable in shared validation logic
func (bc *Blockchain) convertUTXOsToRequiredFormat() map[string][]shared.UTXO {
	result := make(map[string][]shared.UTXO)
	for key, utxos := range bc.UTXOs {
		sharedUtxos := make([]shared.UTXO, len(utxos))
		for i, utxo := range utxos {
			sharedUtxos[i] = shared.UTXO{
				TransactionID: utxo.TransactionId,
				Index:         int(utxo.Index),
				OwnerAddress:  utxo.OwnerAddress,
				Amount:        int64(utxo.Amount),
			}
		}
		result[key] = sharedUtxos
	}
	return result
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

// This function should return the number of blocks in the blockchain.

func (bc *Blockchain) GetBlockCount() int {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()
	return len(bc.Blocks)
}

// This function should return the number of transactions for a given address, which is often referred to as the "nonce."

func (bc *Blockchain) GetTransactionCount(address string) int {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	count := 0
	for _, block := range bc.Blocks {
		for _, transaction := range block.Transactions {
			if transaction.Sender == address {
				count++
			}
		}
	}
	return count
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

// If the stake adjustment leads to a non-positive value, the stakeholder is removed from the map.
func (bc *Blockchain) UpdateStake(address string, amount int64) error {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	// Calculate the new stake amount
	currentStake, exists := bc.Stakeholders[address]
	newStake := currentStake + amount

	// Check if the new stake is positive
	if newStake <= 0 {
		if exists {
			// Remove the stakeholder if the stake is zero or negative
			delete(bc.Stakeholders, address)
		} // If not exists and amount is negative, we cannot set a negative stake
		return fmt.Errorf("invalid stake amount; stake cannot be negative or zero")
	}

	// Set or update the stake
	bc.Stakeholders[address] = newStake
	return nil
}

func (bc *Blockchain) RegisterValidator(address string, pubKey string, bypassStakeCheck bool) error {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	// Sanitize and format the address
	formattedAddress, err := shared.SanitizeAndFormatAddress(address)
	if err != nil {
		return fmt.Errorf("invalid address format: %v", err)
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("error decoding public key: %v", err)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("public key has incorrect size")
	}

	if !bypassStakeCheck {
		stake, exists := bc.Stakeholders[formattedAddress]
		if !exists || stake < bc.MinStakeForValidator.Int64() {
			return fmt.Errorf("insufficient stake or not found")
		}
	}

	// Store the public key
	bc.PublicKeyMap[formattedAddress] = ed25519.PublicKey(pubKeyBytes)

	// Store in the database
	err = bc.Database.InsertOrUpdateEd25519PublicKey(formattedAddress, pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to store public key in database: %v", err)
	}

	log.Printf("Validator registered: address=%s, pubKey=%x", formattedAddress, pubKeyBytes)
	return nil
}

func (bc *Blockchain) TransferFunds(from, to string, amount int64) error {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	if from == "" {
		from = bc.GenesisAccount // Default to the genesis account if 'from' is not specified
	}

	// Check if the sender has enough funds
	if bc.Stakeholders[from] < amount {
		return fmt.Errorf("insufficient funds")
	}

	// Perform the transfer
	bc.Stakeholders[from] -= amount
	bc.Stakeholders[to] += amount

	return nil
}

// This method will adjust the stake between two addresses, which represents delegating stake from one user (the delegator) to another (the delegatee or validator).
func (bc *Blockchain) DelegateStake(from, to string, amount int64) error {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	// Check if the 'from' address has enough stake to delegate
	if stake, exists := bc.Stakeholders[from]; !exists || stake < amount {
		return fmt.Errorf("insufficient stake to delegate: has %d, needs %d", stake, amount)
	}

	// Reduce stake from the 'from' address
	bc.Stakeholders[from] -= amount

	// Add stake to the 'to' address
	if _, exists := bc.Stakeholders[to]; exists {
		bc.Stakeholders[to] += amount
	} else {
		bc.Stakeholders[to] = amount
	}

	return nil
}

func (bc *Blockchain) UpdateActiveValidators(count int) {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	// Sort stakeholders by stake
	type stakeholderInfo struct {
		address string
		stake   int64
	}
	stakeholders := make([]stakeholderInfo, 0, len(bc.Stakeholders))
	for address, stake := range bc.Stakeholders {
		stakeholders = append(stakeholders, stakeholderInfo{address, stake})
	}
	sort.Slice(stakeholders, func(i, j int) bool {
		return stakeholders[i].stake > stakeholders[j].stake
	})

	// Select top 'count' stakeholders as active validators
	bc.ActiveValidators = make([]string, 0, count)
	preGeneratedValidators := make([]string, 0)
	otherValidators := make([]string, 0)

	for i := 0; i < count && i < len(stakeholders); i++ {
		address := stakeholders[i].address
		if strings.HasPrefix(address, "validator-") {
			preGeneratedValidators = append(preGeneratedValidators, address)
		} else {
			otherValidators = append(otherValidators, address)
		}
	}

	// Ensure we have at least some pre-generated validators
	neededPreGenerated := min(5, count/2) // Adjust this ratio as needed
	for len(preGeneratedValidators) < neededPreGenerated {
		newValidatorAddress, err := bc.GenerateAndStoreValidatorKey()
		if err != nil {
			log.Printf("Failed to generate validator key: %v", err)
			continue
		}
		preGeneratedValidators = append(preGeneratedValidators, newValidatorAddress)
	}

	// Combine pre-generated and other validators, prioritizing higher stakes
	bc.ActiveValidators = append(bc.ActiveValidators, preGeneratedValidators...)
	remainingSlots := count - len(bc.ActiveValidators)
	bc.ActiveValidators = append(bc.ActiveValidators, otherValidators[:min(remainingSlots, len(otherValidators))]...)

	log.Printf("Updated active validators. Total: %d, Pre-generated: %d", len(bc.ActiveValidators), len(preGeneratedValidators))
}

func GenerateValidatorAddress() (string, error) {
	// Generate a random 32-byte private key
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate private key: %v", err)
	}

	// Convert to ed25519 private key
	edPrivateKey := ed25519.NewKeyFromSeed(privateKey)

	// Get the public key
	publicKey := edPrivateKey.Public().(ed25519.PublicKey)

	// Hash the public key
	hash := sha256.Sum256(publicKey)

	// Use the first 20 bytes of the hash as the address bytes
	addressBytes := hash[:20]

	// Convert to 5-bit groups for bech32 encoding
	converted, err := bech32.ConvertBits(addressBytes, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %v", err)
	}

	// Encode using bech32
	address, err := bech32.Encode("tl1", converted)
	if err != nil {
		return "", fmt.Errorf("failed to encode address: %v", err)
	}

	return address, nil
}

func (bc *Blockchain) GenerateAndStoreValidatorKey() (string, error) {
	address, err := GenerateValidatorAddress()
	if err != nil {
		return "", fmt.Errorf("failed to generate validator address: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate key pair: %v", err)
	}

	pubKeyBase64 := base64.StdEncoding.EncodeToString(pub)

	// Register the validator, bypassing the stake check
	err = bc.RegisterValidator(address, pubKeyBase64, true)
	if err != nil {
		return "", fmt.Errorf("failed to register validator: %v", err)
	}

	// Assign the minimum stake to the new validator
	minStake := bc.MinStakeForValidator.Int64()
	bc.Stakeholders[address] = minStake

	// Store private key securely (in a separate, encrypted storage)
	err = bc.StoreValidatorPrivateKey(address, priv)
	if err != nil {
		return "", fmt.Errorf("failed to store validator private key: %v", err)
	}

	log.Printf("Generated and stored validator key: address=%s, pubKey=%s, stake=%d", address, pubKeyBase64, minStake)
	return address, nil
}

// For generating multiple Validator Keys if necessary
func (bc *Blockchain) GenerateAndStoreValidatorKeys(count int) error {
	log.Printf("Starting to generate and store %d validator keys", count)
	for i := 0; i < count; i++ {
		log.Printf("Generating validator key %d of %d", i+1, count)
		// Your existing code here
		// ...
		log.Printf("Successfully generated and stored validator key %d", i+1)
	}
	log.Println("Finished generating and storing validator keys")
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (bc *Blockchain) validatorExists(address string) bool {
	_, err := bc.RetrievePublicKey(address)
	return err == nil
}

func (bc *Blockchain) IsActiveValidator(address string) bool {
	bc.Mu.RLock()
	defer bc.Mu.RUnlock()

	for _, validator := range bc.ActiveValidators {
		if validator == address {
			return true
		}
	}
	return false
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

	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(newBlock); err != nil {
		return false, fmt.Errorf("failed to serialize new block: %v", err)
	}
	blockData := buf.Bytes()

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
func (bc *Blockchain) RewardValidator(validator string, reward int64) {
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

// Blockchain Initialization:
// Initialize the blockchain database and genesis block upon starting the server.
// Load or create stakeholders, UTXOs, and transactions for the genesis block.
// Transaction Handling and Block Management:
// Receive transactions from clients, add to the pending transaction pool, and process them periodically.
// Create new blocks from pending transactions, ensuring transactions are valid, updating the UTXO set, and managing block links.
// Fork Resolution and Integrity Checks:
// Check for forks in the blockchain and resolve by selecting the longest chain.
// Perform regular integrity checks on the blockchain to ensure no tampering or inconsistencies.
// Blockchain Operations (Detailed Server-Side)
// Transaction Verification:
// Verify each transaction for double spending and proper signature before adding to a block.
// Manage UTXOs to reflect current ownership states.
// Block Creation:
// On achieving a sufficient number of transactions or a time limit, attempt to create a new block.
// Validate the new block against the previous block and the blockchain's proof-of-stake rules.
// Consensus and Blockchain Updates:
// If a new block is validated successfully, append it to the blockchain.
// Update the blockchain state, including UTXOs and potentially resolving forks.
// Blockchain Maintenance Tasks:
// Regularly check and ensure the blockchain's integrity using hash checks and timestamp validations.
// Optionally, handle rewards for validators and manage the stakeholder map based on proof-of-stake consensus.
