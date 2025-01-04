package core

import (
	"bytes"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"crypto/aes"
	"crypto/cipher"
	stdEd25519 "crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"math/big"
	"sort"

	"github.com/shopspring/decimal"
	"golang.org/x/crypto/ed25519"
	xEd25519 "golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"

	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/database"
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/state"
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

	ConsensusManager *ConsensusManager

	ActiveValidators []string

	MinStakeForValidator *big.Int

	OnNewBlock func(*Block) // Callback function for when a new block is added

	ValidatorKeys          *ValidatorKeyStore
	TestMode               bool
	OnTransactionProcessed func(*thrylos.Transaction)
	OnBalanceUpdate        func(address string, balance int64)

	StateManager *state.StateManager

	StateNetwork   shared.NetworkInterface
	StakingService *StakingService
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

type ValidatorKeyStore struct {
	keys map[string]ed25519.PrivateKey
	mu   sync.RWMutex
}

type BlockchainConfig struct {
	DataDir           string
	AESKey            []byte
	GenesisAccount    string
	TestMode          bool
	DisableBackground bool
	StateManager      *state.StateManager
}

func (vks *ValidatorKeyStore) StoreKey(address string, privKey ed25519.PrivateKey) error {
	vks.mu.Lock()
	defer vks.mu.Unlock()

	vks.keys[address] = privKey
	return nil
}

func (vks *ValidatorKeyStore) GetKey(address string) (ed25519.PrivateKey, bool) {
	vks.mu.RLock()
	defer vks.mu.RUnlock()

	privateKey, exists := vks.keys[address]
	return privateKey, exists
}

const (
	keyLen    = 32 // AES-256
	nonceSize = 12
	saltSize  = 32
)

var ErrInvalidKeySize = errors.New("invalid key size")

func deriveKey(password []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, keyLen)
}

func encryptPrivateKey(privKey ed25519.PrivateKey) ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(salt)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, privKey, nil)
	return append(append(salt, nonce...), ciphertext...), nil
}

func decryptPrivateKey(encryptedKey []byte) (ed25519.PrivateKey, error) {
	if len(encryptedKey) < saltSize+nonceSize+1 {
		return nil, ErrInvalidKeySize
	}

	salt := encryptedKey[:saltSize]
	nonce := encryptedKey[saltSize : saltSize+nonceSize]
	ciphertext := encryptedKey[saltSize+nonceSize:]

	block, err := aes.NewCipher(salt)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if len(plaintext) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKeySize
	}

	return ed25519.PrivateKey(plaintext), nil
}

func NewValidatorKeyStore() *ValidatorKeyStore {
	return &ValidatorKeyStore{
		keys: make(map[string]ed25519.PrivateKey),
	}
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

func ConvertToBech32Address(address string) (string, error) {
	// Check if the address is already in Bech32 format
	if strings.HasPrefix(address, "tl1") {
		return address, nil
	}

	// Try to decode the address as hexadecimal
	addressBytes, err := hex.DecodeString(address)
	if err == nil {
		// Take the first 20 bytes (40 characters of the hex string)
		// This is similar to how Ethereum addresses are derived from public keys
		if len(addressBytes) > 20 {
			addressBytes = addressBytes[:20]
		}

		// Convert to 5-bit groups for Bech32 encoding
		converted, err := bech32.ConvertBits(addressBytes, 8, 5, true)
		if err != nil {
			return "", fmt.Errorf("failed to convert bits: %v", err)
		}

		// Encode to Bech32
		bech32Address, err := bech32.Encode("tl1", converted)
		if err != nil {
			return "", fmt.Errorf("failed to encode address to Bech32: %v", err)
		}

		return bech32Address, nil
	}

	// If the address is not in hexadecimal format, try to use it directly
	return address, nil
}

// NewBlockchain initializes and returns a new instance of a Blockchain. It sets up the necessary
// infrastructure, including the genesis block and the database connection for persisting the blockchain state.
func NewBlockchainWithConfig(config *BlockchainConfig) (*Blockchain, shared.BlockchainDBInterface, error) {
	// Initialize the database
	db, err := database.InitializeDatabase(config.DataDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize the blockchain database: %v", err)
	}
	bdb := database.NewBlockchainDB(db, config.AESKey)
	log.Println("BlockchainDB created")

	// Create the genesis block
	genesis := NewGenesisBlock()
	log.Println("Genesis block created")

	// Initialize the map for public keys
	publicKeyMap := make(map[string]xEd25519.PublicKey)

	// Initialize Stakeholders map with the genesis account
	totalSupply := big.NewInt(120_000_000) // 120 million tokens
	totalSupplyNano := ThrylosToNano(float64(totalSupply.Int64()))

	log.Printf("Initializing genesis account with total supply: %d THR", totalSupplyNano/1e7)

	// Convert the genesis account address to Bech32 format
	bech32GenesisAccount, err := ConvertToBech32Address(config.GenesisAccount)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert genesis account to Bech32: %v", err)
	}

	// Use bech32GenesisAccount instead of genesisAccount from here on
	stakeholdersMap := make(map[string]int64)
	stakeholdersMap[bech32GenesisAccount] = totalSupplyNano // Genesis holds total supply including staking reserve

	log.Printf("Initializing genesis account: %s", config.GenesisAccount)

	// Generate a new key pair for the genesis account
	log.Println("Generating key pair for genesis account")
	genesisPublicKey, genesisPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate genesis account key pair: %v", err)
	}
	log.Println("Genesis account key pair generated successfully")

	log.Println("Storing public key for genesis account")
	err = bdb.StoreValidatorPublicKey(bech32GenesisAccount, genesisPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store genesis account public key: %v", err)
	}
	log.Println("Genesis account public key stored successfully")

	// Create genesis transaction
	genesisTx := &thrylos.Transaction{
		Id:        "genesis_tx_" + bech32GenesisAccount,
		Timestamp: time.Now().Unix(),
		Outputs: []*thrylos.UTXO{{
			OwnerAddress: config.GenesisAccount,
			Amount:       totalSupplyNano,
		}},
		Signature: []byte("genesis_signature"),
	}

	// Initialize UTXO map with the genesis transaction
	utxoMap := make(map[string][]*thrylos.UTXO)
	utxoKey := fmt.Sprintf("%s:%d", genesisTx.Id, 0)
	utxoMap[utxoKey] = []*thrylos.UTXO{genesisTx.Outputs[0]}

	genesis.Transactions = []*thrylos.Transaction{genesisTx}

	stateNetwork := shared.NewDefaultNetwork()
	stateManager := state.NewStateManager(stateNetwork, 4)

	blockchain := &Blockchain{
		Blocks:              []*Block{genesis},
		Genesis:             genesis,
		Stakeholders:        stakeholdersMap,
		Database:            bdb,
		PublicKeyMap:        publicKeyMap,
		UTXOs:               utxoMap,
		Forks:               make([]*Fork, 0),
		GenesisAccount:      bech32GenesisAccount,
		PendingTransactions: make([]*thrylos.Transaction, 0),
		ActiveValidators:    make([]string, 0),
		StateNetwork:        stateNetwork,
		ValidatorKeys:       NewValidatorKeyStore(),
		TestMode:            config.TestMode,
		StateManager:        stateManager,
	}

	// Now store the private key for the genesis account
	log.Println("Storing private key for genesis account")
	blockchain.ValidatorKeys.StoreKey(bech32GenesisAccount, genesisPrivateKey)

	// Verify that the key was stored correctly
	// Verify that the key was stored correctly
	storedKey, exists := blockchain.ValidatorKeys.GetKey(bech32GenesisAccount)
	if !exists {
		return nil, nil, fmt.Errorf("failed to store genesis account private key: key not found after storage")
	}
	if !bytes.Equal(storedKey, genesisPrivateKey) {
		return nil, nil, fmt.Errorf("failed to store genesis account private key: stored key does not match original")
	}
	log.Println("Genesis account private key stored and verified successfully")

	// Add the genesis public key to the publicKeyMap
	blockchain.PublicKeyMap[bech32GenesisAccount] = genesisPublicKey
	log.Println("Genesis account public key added to publicKeyMap")

	// When logging the genesis account
	log.Printf("Genesis account %s initialized with total supply: %d", bech32GenesisAccount, totalSupplyNano)

	// Calculate and set the minimum stake for validators
	minStakePercentage := big.NewFloat(0.001) // 0.1%

	minStake := new(big.Float).Mul(new(big.Float).SetInt(totalSupply), minStakePercentage)

	blockchain.MinStakeForValidator = new(big.Int)
	minStake.Int(blockchain.MinStakeForValidator) // Convert big.Float to big.Int

	// Initialize ConsensusManager which provides sufficient consensus management
	blockchain.ConsensusManager = NewConsensusManager(blockchain)

	log.Println("Generating and storing validator keys")
	validatorAddresses, err := blockchain.GenerateAndStoreValidatorKeys(2)
	if err != nil {
		log.Printf("Warning: Failed to generate validator keys: %v", err)
		return nil, nil, fmt.Errorf("failed to generate validator keys: %v", err)
	}
	log.Println("Validator keys generated and stored")

	// Add generated validators to ActiveValidators list
	blockchain.ActiveValidators = append(blockchain.ActiveValidators, validatorAddresses...)
	log.Printf("Added %d validators to ActiveValidators list", len(validatorAddresses))

	// Add genesis account as a validator if it's not already included
	if !contains(blockchain.ActiveValidators, bech32GenesisAccount) {
		blockchain.ActiveValidators = append(blockchain.ActiveValidators, bech32GenesisAccount)
		log.Printf("Added genesis account to ActiveValidators list")
	}

	log.Printf("Total ActiveValidators: %d", len(blockchain.ActiveValidators))

	// Add this check
	log.Println("Verifying stored validator keys")
	keys, err := bdb.GetAllValidatorPublicKeys()
	if err != nil {
		log.Printf("Failed to retrieve all validator public keys: %v", err)
		return nil, nil, fmt.Errorf("failed to verify stored validator keys: %v", err)
	}
	log.Printf("Retrieved %d validator public keys", len(keys))

	log.Println("Loading all validator public keys")
	err = blockchain.LoadAllValidatorPublicKeys()
	if err != nil {
		log.Printf("Warning: Failed to load all validator public keys: %v", err)
	}
	log.Println("Validator public keys loaded")

	log.Println("Checking validator key consistency")
	blockchain.CheckValidatorKeyConsistency()
	log.Println("Validator key consistency check completed")

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

	log.Printf("Genesis account %s initialized with total supply: %d", config.GenesisAccount, totalSupplyNano)

	log.Println("NewBlockchain initialization completed successfully")

	// Add after state sync loop start and before return
	blockchain.StateManager.StartStateSyncLoop()
	log.Println("State synchronization loop started")

	// Add shutdown handler
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("Stopping state synchronization...")
		blockchain.StateManager.StopStateSyncLoop()
	}()

	// Initialize staking service with proper configuration
	log.Println("Initializing staking service...")
	blockchain.StakingService = NewStakingService(blockchain)
	log.Printf("Staking service initialized with:")
	log.Printf("- Minimum stake: %d THRYLOS", blockchain.StakingService.pool.MinStakeAmount/1e7)
	log.Printf("- Fixed yearly reward: 4.8M THRYLOS")
	log.Printf("- Current total supply: 120M THRYLOS")

	// Modify background process initialization based on DisableBackground flag
	if !config.DisableBackground {
		go func() {
			log.Println("Starting daily staking reward distribution process")
			for {
				if err := blockchain.StakingService.DistributeRewards(); err != nil {
					log.Printf("Error distributing staking rewards: %v", err)
				}
				// Sleep for 1 hour instead of 1 minute since we only need to check daily
				// This reduces unnecessary checks while ensuring we don't miss the 24-hour mark
				time.Sleep(time.Hour)
			}
		}()

		// Start periodic validator update in a separate goroutine
		go func() {
			log.Println("Starting periodic validator update")
			blockchain.StartPeriodicValidatorUpdate(15 * time.Minute)
		}()

		// Start state synchronization loop
		blockchain.StateManager.StartStateSyncLoop()
		log.Println("State synchronization loop started")

		// Add shutdown handler
		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			<-c
			log.Println("Stopping state synchronization...")
			blockchain.StateManager.StopStateSyncLoop()
		}()
	} else {
		// In test mode, log that background processes are disabled
		log.Println("Background processes disabled for testing")
	}

	log.Println("NewBlockchain initialization completed successfully")
	return blockchain, bdb, nil
}

func (bc *Blockchain) GetTotalSupply() int64 {
	totalSupply := int64(0)
	for _, balance := range bc.Stakeholders {
		totalSupply += balance
	}
	return totalSupply
}

func (bc *Blockchain) GetEffectiveInflationRate() float64 {
	currentTotalSupply := float64(bc.GetTotalSupply()) / 1e7
	yearlyReward := 4_800_000.0 // Fixed 4.8M

	// Calculate effective rate (will decrease as total supply grows)
	effectiveRate := (yearlyReward / currentTotalSupply) * 100
	return effectiveRate
}

func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
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

func (bc *Blockchain) CreateInitialWalletUTXO(address string, initialBalance int64) error {
	utxo := shared.UTXO{
		OwnerAddress:  address,
		Amount:        initialBalance,
		TransactionID: fmt.Sprintf("genesis-%s", address),
		IsSpent:       false,
		Index:         0, // Use 0 for initial UTXO
	}

	return bc.Database.AddUTXO(utxo)
}

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

// Always deals with nanoTHRYLOS as int64
func (bc *Blockchain) GetBalance(address string) (int64, error) {
	var balance int64 = 0
	utxos, err := bc.Database.GetUTXOsForAddress(address)
	if err != nil {
		return 0, err
	}

	for _, utxo := range utxos {
		if !utxo.IsSpent {
			balance += utxo.Amount
		}
	}
	return balance, nil
}

// ConvertToThrylos converts nanoTHRYLOS to THRYLOS
func ConvertToThrylos(nanoThrylos decimal.Decimal) decimal.Decimal {
	return nanoThrylos.Div(decimal.NewFromInt(1e7))
}

// ConvertToNanoThrylos converts THRYLOS to nanoTHRYLOS
func ConvertToNanoThrylos(thrylos decimal.Decimal) decimal.Decimal {
	return thrylos.Mul(decimal.NewFromInt(1e7))
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

func (bc *Blockchain) ProcessPendingTransactionsWithBatch(validator string, batch []*thrylos.Transaction) (*Block, error) {
	// Similar to ProcessPendingTransactions but works with the provided batch
	return bc.ProcessPendingTransactions(validator)
}

// Load all Validator public keys into Memory
func (bc *Blockchain) LoadAllValidatorPublicKeys() error {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	log.Println("Loading all validator public keys")

	for address := range bc.Stakeholders {
		log.Printf("Attempting to load public key for stakeholder: %s", address)
		pubKey, err := bc.Database.RetrieveValidatorPublicKey(address)
		if err != nil {
			log.Printf("Failed to load public key for stakeholder %s: %v", address, err)
			continue
		}

		if err != nil {
			log.Printf("Failed to load public key for stakeholder %s: %v", address, err)
			continue
		}

		if len(pubKey) > 0 {
			bc.PublicKeyMap[address] = ed25519.PublicKey(pubKey)
			log.Printf("Loaded public key for validator: %s", address)
		}
	}

	log.Printf("Loaded public keys for %d validators", len(bc.PublicKeyMap))
	return nil
}

func (bc *Blockchain) GetValidatorPublicKey(validatorAddress string) (ed25519.PublicKey, error) {
	// Retrieve the public key from your storage mechanism
	// This is just an example, adjust according to your actual implementation
	publicKeyBytes, err := bc.Database.RetrieveValidatorPublicKey(validatorAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve public key for validator %s: %v", validatorAddress, err)
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size for validator %s", validatorAddress)
	}

	return ed25519.PublicKey(publicKeyBytes), nil
}

// CreateBlock generates a new block with the given transactions, validator, previous hash, and timestamp.
// This method encapsulates the logic for building a block to be added to the blockchain.
func (bc *Blockchain) CreateUnsignedBlock(transactions []*thrylos.Transaction, validator string) (*Block, error) {
	prevBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := &Block{
		Index:        int32(len(bc.Blocks)),
		Timestamp:    time.Now().Unix(),
		Transactions: transactions,
		Validator:    validator,
		PrevHash:     prevBlock.Hash,
		// Hash and Signature fields are left empty
	}

	// Initialize Verkle tree before computing hash
	if err := newBlock.InitializeVerkleTree(); err != nil {
		return nil, fmt.Errorf("failed to initialize Verkle tree: %v", err)
	}

	// Compute the hash
	newBlock.Hash = newBlock.ComputeHash()

	return newBlock, nil
}

func (bc *Blockchain) VerifySignedBlock(signedBlock *Block) error {
	// Verify the block's hash
	computedHash := signedBlock.ComputeHash()
	if !bytes.Equal(computedHash, signedBlock.Hash) {
		log.Printf("Block hash mismatch. Computed: %x, Block: %x", computedHash, signedBlock.Hash)
		return errors.New("invalid block hash")
	}

	publicKey, err := bc.GetValidatorPublicKey(signedBlock.Validator)
	if err != nil {
		log.Printf("Failed to get validator public key: %v", err)
		return fmt.Errorf("failed to get validator public key: %v", err)
	}
	log.Printf("Retrieved public key for verification: %x", publicKey)

	// Also try to retrieve the public key directly from the database
	storedPublicKey, err := bc.Database.RetrieveValidatorPublicKey(signedBlock.Validator)
	if err != nil {
		log.Printf("Failed to retrieve stored public key for validator %s: %v", signedBlock.Validator, err)
	} else {
		log.Printf("Stored public key for validator %s: %x", signedBlock.Validator, storedPublicKey)
		if !bytes.Equal(publicKey, storedPublicKey) {
			log.Printf("WARNING: Retrieved public key does not match stored public key for validator %s", signedBlock.Validator)
		}
	}

	// Verify the signature
	if !ed25519.Verify(publicKey, signedBlock.Hash, signedBlock.Signature) {
		log.Printf("Signature verification failed. Validator: %s, Block Hash: %x, Signature: %x",
			signedBlock.Validator, signedBlock.Hash, signedBlock.Signature)
		return errors.New("invalid block signature")
	}

	log.Printf("Block signature verified successfully for validator: %s", signedBlock.Validator)
	return nil
}
func (bc *Blockchain) CheckValidatorKeyConsistency() error {
	log.Println("Checking validator key consistency")

	allPublicKeys, err := bc.Database.GetAllValidatorPublicKeys()
	if err != nil {
		return fmt.Errorf("failed to retrieve all validator public keys: %v", err)
	}

	log.Printf("Total stored validator public keys: %d", len(allPublicKeys))
	log.Printf("Total active validators: %d", len(bc.ActiveValidators))

	for address, publicKey := range allPublicKeys {
		log.Printf("Checking consistency for validator: %s", address)
		log.Printf("Stored public key for %s: %x", address, publicKey)

		if bc.IsActiveValidator(address) {
			log.Printf("Validator %s is active", address)

			privateKey, bech32Address, err := bc.GetValidatorPrivateKey(address)
			if err != nil {
				log.Printf("Failed to retrieve private key for validator %s: %v", address, err)
				continue
			}

			log.Printf("Retrieved private key for %s, Bech32 address: %s", address, bech32Address)

			derivedPublicKey := privateKey.Public().(stdEd25519.PublicKey)
			log.Printf("Derived public key for %s: %x", address, derivedPublicKey)

			if !bytes.Equal(publicKey, derivedPublicKey) {
				log.Printf("Key mismatch for validator %s (Bech32: %s):", address, bech32Address)
				log.Printf("  Stored public key:  %x", publicKey)
				log.Printf("  Derived public key: %x", derivedPublicKey)
				return fmt.Errorf("key mismatch for active validator %s (Bech32: %s): stored public key does not match derived public key",
					address, bech32Address)
			}

			log.Printf("Keys consistent for active validator %s", address)
		} else {
			log.Printf("Validator %s is not active", address)
		}
	}

	for _, activeAddress := range bc.ActiveValidators {
		if _, exists := allPublicKeys[activeAddress]; !exists {
			log.Printf("Active validator %s does not have a stored public key", activeAddress)
			return fmt.Errorf("active validator %s does not have a stored public key", activeAddress)
		}
	}

	log.Println("Validator key consistency check completed")
	return nil
}

func (bc *Blockchain) SignBlock(block *Block, validatorAddress string) ([]byte, error) {
	privateKey, bech32Address, err := bc.GetValidatorPrivateKey(validatorAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get validator private key: %v", err)
	}

	// The Bech32 address is already returned by GetValidatorPrivateKey, so we don't need to convert it again
	block.Validator = bech32Address

	blockData, err := block.SerializeForSigning()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize block for signing: %v", err)
	}

	signature := stdEd25519.Sign(privateKey, blockData)
	return signature, nil
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

func (bc *Blockchain) IsSlashed(validator string) bool {
	// Check if validator is in slashed state
	if stake, exists := bc.Stakeholders[validator]; exists {
		return stake < bc.MinStakeForValidator.Int64() // Validator is slashed if below min stake
	}
	return false
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
	// Check if PrevHash matches the hash of the previous block
	if !bytes.Equal(newBlock.PrevHash, prevBlock.Hash) {
		fmt.Printf("Invalid previous hash in block %d\n", newBlock.Index)
		return false
	}

	// Validate the block's proof of stake
	if !bc.VerifyPoSRules(*newBlock) {
		fmt.Printf("Invalid block %d due to PoS rules: validator was %s\n", newBlock.Index, newBlock.Validator)
		return false
	}

	// Validate the block's hash
	computedHash := newBlock.ComputeHash()
	if !bytes.Equal(newBlock.Hash, computedHash) {
		fmt.Printf("Invalid hash in block %d: expected %x, got %x\n", newBlock.Index, computedHash, newBlock.Hash)
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
			return xEd25519.PublicKey{}, err
		}
		return pubKey, nil
	}

	// Convert UTXOs to proto format if needed
	protoUTXOs := make(map[string][]*thrylos.UTXO)
	for key, utxos := range bc.UTXOs {
		protoUTXOs[key] = utxos
	}

	// Only verify transaction data, no proof verification needed
	isValid, err := shared.VerifyTransactionData(tx, protoUTXOs, getEd25519PublicKeyFunc)
	if err != nil {
		fmt.Printf("Error during transaction data verification: %v\n", err)
		return false, err
	}
	if !isValid {
		fmt.Println("Transaction data validation failed")
		return false, nil
	}

	return true, nil
}

// AddPendingTransaction adds a new transaction to the pool of pending transactions.
func (bc *Blockchain) AddPendingTransaction(tx *thrylos.Transaction) error {
	// Start a database transaction
	txn, err := bc.Database.BeginTransaction()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer bc.Database.RollbackTransaction(txn)

	// Store the transaction with initial "pending" status
	txKey := []byte("transaction-" + tx.Id)
	tx.Status = "pending"
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("error marshaling transaction: %v", err)
	}

	if err := bc.Database.SetTransaction(txn, txKey, txJSON); err != nil {
		return fmt.Errorf("error storing transaction: %v", err)
	}

	// Add to pending transactions
	bc.Mu.Lock()
	bc.PendingTransactions = append(bc.PendingTransactions, tx)
	bc.Mu.Unlock()

	// Commit the database transaction
	if err := bc.Database.CommitTransaction(txn); err != nil {
		return fmt.Errorf("error committing transaction: %v", err)
	}

	log.Printf("Transaction %s successfully added to pending pool. Total pending: %d",
		tx.Id, len(bc.PendingTransactions))

	return nil
}

// ProcessPendingTransactions processes all pending transactions, attempting to form a new block.
func (bc *Blockchain) ProcessPendingTransactions(validator string) (*Block, error) {
	// First, verify validator status before acquiring locks
	if !bc.IsActiveValidator(validator) {
		return nil, fmt.Errorf("invalid validator: %s", validator)
	}

	// Take a snapshot of pending transactions under lock
	bc.Mu.Lock()
	if len(bc.PendingTransactions) == 0 {
		bc.Mu.Unlock()
		return nil, nil // Nothing to process
	}
	pendingTransactions := make([]*thrylos.Transaction, len(bc.PendingTransactions))
	copy(pendingTransactions, bc.PendingTransactions)
	bc.Mu.Unlock()

	// Start database transaction
	txContext, err := bc.Database.BeginTransaction()
	if err != nil {
		return nil, fmt.Errorf("database transaction error: %v", err)
	}
	defer bc.Database.RollbackTransaction(txContext)

	// Process transactions in batches
	successfulTransactions := make([]*thrylos.Transaction, 0, len(pendingTransactions))
	for _, tx := range pendingTransactions {
		if err := bc.processTransactionInBlock(txContext, tx); err != nil {
			log.Printf("Transaction %s failed: %v", tx.Id, err)
			continue
		}
		successfulTransactions = append(successfulTransactions, tx)
	}

	// Create and sign block
	unsignedBlock, err := bc.CreateUnsignedBlock(successfulTransactions, validator)
	if err != nil {
		return nil, fmt.Errorf("block creation failed: %v", err)
	}

	signedBlock, err := bc.SimulateValidatorSigning(unsignedBlock)
	if err != nil {
		return nil, fmt.Errorf("block signing failed: %v", err)
	}

	// Commit database changes
	if err := bc.Database.CommitTransaction(txContext); err != nil {
		return nil, fmt.Errorf("commit failed: %v", err)
	}

	// Only after successful commit do we update blockchain state
	bc.Mu.Lock()
	bc.Blocks = append(bc.Blocks, signedBlock)
	// Remove processed transactions from pending pool
	bc.PendingTransactions = bc.PendingTransactions[len(successfulTransactions):]
	bc.Mu.Unlock()

	// Async notifications
	go func() {
		for _, tx := range signedBlock.Transactions {
			bc.UpdateTransactionStatus(tx.Id, "included", signedBlock.Hash)
			if bc.OnTransactionProcessed != nil {
				bc.OnTransactionProcessed(tx)
			}
			bc.notifyBalanceUpdates(tx)
		}
	}()

	return signedBlock, nil
}

// First, ensure when creating transaction inputs we set the original transaction ID
func (bc *Blockchain) processTransactionInBlock(txContext *shared.TransactionContext, tx *thrylos.Transaction) error {
	// Mark input UTXOs as spent
	for _, input := range tx.Inputs {
		// Validate input fields
		if input.TransactionId == "" {
			return fmt.Errorf("input UTXO has no transaction_id field set")
		}

		utxo := shared.UTXO{
			TransactionID: input.TransactionId, // This must be the genesis or previous transaction ID
			Index:         int(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        int64(input.Amount),
			IsSpent:       false,
		}

		// Debug logging
		log.Printf("Processing input UTXO: TransactionID=%s, Index=%d, Owner=%s, Amount=%d",
			utxo.TransactionID, utxo.Index, utxo.OwnerAddress, utxo.Amount)

		if err := bc.Database.MarkUTXOAsSpent(txContext, utxo); err != nil {
			return fmt.Errorf("failed to mark UTXO as spent: %v", err)
		}
	}

	// Create new UTXOs for outputs with the current transaction ID
	for i, output := range tx.Outputs {
		newUTXO := shared.UTXO{
			TransactionID: tx.Id, // Use current transaction's ID for new UTXOs
			Index:         i,
			OwnerAddress:  output.OwnerAddress,
			Amount:        int64(output.Amount),
			IsSpent:       false,
		}

		// Debug logging
		log.Printf("Creating new UTXO: TransactionID=%s, Index=%d, Owner=%s, Amount=%d",
			newUTXO.TransactionID, newUTXO.Index, newUTXO.OwnerAddress, newUTXO.Amount)

		if err := bc.Database.AddNewUTXO(txContext, newUTXO); err != nil {
			return fmt.Errorf("failed to create new UTXO: %v", err)
		}
	}

	return nil
}

func (bc *Blockchain) notifyBalanceUpdates(tx *thrylos.Transaction) {
	if bc.OnBalanceUpdate == nil {
		return
	}

	addresses := make(map[string]bool)
	addresses[tx.Sender] = true
	for _, output := range tx.Outputs {
		addresses[output.OwnerAddress] = true
	}

	for address := range addresses {
		balance, err := bc.GetBalance(address)
		if err != nil {
			log.Printf("Failed to get balance for %s: %v", address, err)
			continue
		}
		bc.OnBalanceUpdate(address, balance)
	}
}

func (bc *Blockchain) SimulateValidatorSigning(unsignedBlock *Block) (*Block, error) {
	log.Printf("Simulating block signing for validator: %s", unsignedBlock.Validator)

	privateKey, bech32Address, err := bc.GetValidatorPrivateKey(unsignedBlock.Validator)
	if err != nil {
		log.Printf("Failed to get validator private key: %v", err)
		return nil, fmt.Errorf("failed to get validator private key: %v", err)
	}

	// Log a hash of the private key for security reasons
	privateKeyHash := sha256.Sum256(privateKey)
	log.Printf("Private key hash used for signing: %x", privateKeyHash)

	// Update the block's validator address to the Bech32 format
	unsignedBlock.Validator = bech32Address
	log.Printf("Updated block validator to Bech32 address: %s", bech32Address)

	// Generate the block hash
	blockHash := unsignedBlock.ComputeHash()
	log.Printf("Signing block hash: %x", blockHash)

	// Sign the block hash
	signature := ed25519.Sign(privateKey, blockHash)
	unsignedBlock.Signature = signature
	unsignedBlock.Hash = blockHash

	log.Printf("Block signed successfully for validator: %s", unsignedBlock.Validator)
	log.Printf("Signature: %x", signature)

	// Verify the signature immediately after signing
	publicKey := privateKey.Public().(ed25519.PublicKey)
	log.Printf("Public key derived from private key: %x", publicKey)

	// Verify that this public key is stored correctly
	storedPublicKey, err := bc.Database.RetrieveValidatorPublicKey(bech32Address)
	if err != nil {
		log.Printf("Failed to retrieve stored public key for validator %s: %v", bech32Address, err)
	} else {
		log.Printf("Stored public key for validator %s: %x", bech32Address, storedPublicKey)
		if !bytes.Equal(publicKey, storedPublicKey) {
			log.Printf("WARNING: Derived public key does not match stored public key for validator %s", bech32Address)
		}
	}

	return unsignedBlock, nil
}

func (bc *Blockchain) UpdateTransactionStatus(txID string, status string, blockHash []byte) error {
	// Begin a new database transaction
	txn, err := bc.Database.BeginTransaction()
	if err != nil {
		return fmt.Errorf("failed to begin database transaction: %v", err)
	}
	defer bc.Database.RollbackTransaction(txn)

	// Retrieve the existing transaction
	txKey := []byte("transaction-" + txID)
	txItem, err := txn.Txn.Get(txKey)
	if err != nil {
		// If transaction doesn't exist, create a new one
		tx := &thrylos.Transaction{
			Id:        txID,
			Status:    status,
			BlockHash: blockHash,
			// Set other required fields that you have available
		}
		txJSON, err := json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("error marshaling new transaction: %v", err)
		}
		if err := bc.Database.SetTransaction(txn, txKey, txJSON); err != nil {
			return fmt.Errorf("error storing new transaction: %v", err)
		}
	} else {
		// Update existing transaction
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

		// Serialize and store the updated transaction
		updatedTxJSON, err := json.Marshal(tx)
		if err != nil {
			return fmt.Errorf("error marshaling updated transaction: %v", err)
		}
		if err := bc.Database.SetTransaction(txn, txKey, updatedTxJSON); err != nil {
			return fmt.Errorf("error updating transaction: %v", err)
		}
	}

	// Commit the transaction
	if err := bc.Database.CommitTransaction(txn); err != nil {
		return fmt.Errorf("error committing transaction update: %v", err)
	}

	log.Printf("Transaction %s status updated to %s in block %x", txID, status, blockHash)
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
	// First, try to parse id as a block index
	if index, err := strconv.Atoi(id); err == nil {
		// id is a valid integer, so we treat it as a block index
		if index >= 0 && index < len(bc.Blocks) {
			block := bc.Blocks[index]
			log.Printf("Block found by index: Index=%d, Transactions=%v", block.Index, block.Transactions)
			return block, nil
		}
	}

	// If id is not a valid index, try to match it as a hash
	idBytes, err := hex.DecodeString(id)
	if err != nil {
		log.Printf("Invalid block ID format: %s", id)
		return nil, errors.New("invalid block ID format")
	}

	// Iterate over blocks and find by hash
	for _, block := range bc.Blocks {
		if bytes.Equal(block.Hash, idBytes) {
			log.Printf("Block found by hash: Index=%d, Transactions=%v", block.Index, block.Transactions)
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
	log.Printf("Entering RegisterValidator function for address: %s", address)

	lockChan := make(chan struct{})
	go func() {
		bc.Mu.Lock()
		close(lockChan)
	}()

	select {
	case <-lockChan:
		log.Printf("Lock acquired for address: %s", address)
		defer func() {
			bc.Mu.Unlock()
			log.Printf("Lock released for address: %s", address)
		}()
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timeout while acquiring lock for address: %s", address)
	}

	// Sanitize and format the address
	formattedAddress, err := shared.SanitizeAndFormatAddress(address)
	if err != nil {
		log.Printf("Invalid address format for %s: %v", address, err)
		return fmt.Errorf("invalid address format: %v", err)
	}
	log.Printf("Formatted address: %s", formattedAddress)

	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("error decoding public key: %v", err)
	}

	// Store the public key
	err = bc.Database.StoreValidatorPublicKey(formattedAddress, pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to store validator public key: %v", err)
	}
	log.Printf("Decoded public key length for %s: %d", formattedAddress, len(pubKeyBytes))

	// Store in memory
	bc.PublicKeyMap[formattedAddress] = ed25519.PublicKey(pubKeyBytes)
	log.Printf("Stored public key in memory for address: %s", formattedAddress)

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		log.Printf("Public key has incorrect size for %s: %d", formattedAddress, len(pubKeyBytes))
		return fmt.Errorf("public key has incorrect size")
	}

	log.Printf("Public key size verified for %s", formattedAddress)

	if !bypassStakeCheck {
		stake, exists := bc.Stakeholders[formattedAddress]
		if !exists || stake < bc.MinStakeForValidator.Int64() {
			log.Printf("Insufficient stake for %s: exists=%v, stake=%d, minStake=%d", formattedAddress, exists, stake, bc.MinStakeForValidator.Int64())
			return fmt.Errorf("insufficient stake or not found")
		}
	}

	log.Printf("Stake check bypassed or passed for %s", formattedAddress)

	// Store the public key
	bc.PublicKeyMap[formattedAddress] = ed25519.PublicKey(pubKeyBytes)
	log.Printf("Stored public key in memory for address: %s", formattedAddress)

	// Store in the database with a timeout
	log.Printf("Attempting to store public key in database for address: %s", formattedAddress)
	dbChan := make(chan error, 1)
	go func() {
		dbChan <- bc.Database.InsertOrUpdateEd25519PublicKey(formattedAddress, pubKeyBytes)
	}()

	// Store the public key
	err = bc.Database.StoreValidatorPublicKey(address, pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to store validator public key: %v", err)
	}

	select {
	case err := <-dbChan:
		if err != nil {
			log.Printf("Failed to store public key in database for %s: %v", formattedAddress, err)
			return fmt.Errorf("failed to store public key in database: %v", err)
		}
	case <-time.After(5 * time.Second):
		log.Printf("Database operation timed out for %s", formattedAddress)
		return fmt.Errorf("database operation timed out")
	}

	log.Printf("Successfully stored public key in database for address: %s", formattedAddress)

	// Assign the minimum stake to the new validator
	minStake := bc.MinStakeForValidator.Int64()
	bc.Stakeholders[formattedAddress] = minStake
	log.Printf("Assigned minimum stake %d to validator %s", minStake, formattedAddress)

	log.Printf("Validator registered successfully: address=%s", formattedAddress)
	return nil
}

func (bc *Blockchain) StoreValidatorPrivateKey(address string, privKey ed25519.PrivateKey) error {
	log.Printf("Storing private key for validator: %s", address)
	if err := bc.ValidatorKeys.StoreKey(address, privKey); err != nil {
		log.Printf("Failed to store private key for validator %s: %v", address, err)
		return fmt.Errorf("failed to store private key for validator %s: %v", address, err)
	}
	log.Printf("Private key for validator %s stored securely", address)
	return nil
}

func (bc *Blockchain) GetValidatorPrivateKey(validatorAddress string) (ed25519.PrivateKey, string, error) {
	log.Printf("Attempting to retrieve private key for validator: %s", validatorAddress)

	// Check if the validator is active
	if !bc.IsActiveValidator(validatorAddress) {
		log.Printf("Validator %s is not in the active validator list", validatorAddress)
		return nil, "", fmt.Errorf("validator is not active: %s", validatorAddress)
	}

	// Retrieve the private key from the ValidatorKeys store
	privateKey, exists := bc.ValidatorKeys.GetKey(validatorAddress)
	if !exists {
		log.Printf("Failed to retrieve private key for validator %s", validatorAddress)
		return nil, "", fmt.Errorf("failed to retrieve private key for validator %s", validatorAddress)
	}

	// Convert the validator address to Bech32 format
	bech32Address, err := ConvertToBech32Address(validatorAddress)
	if err != nil {
		log.Printf("Failed to convert validator address %s to Bech32 format: %v", validatorAddress, err)
		return privateKey, "", err
	}

	return privateKey, bech32Address, nil
}

func generateBech32Address(publicKey ed25519.PublicKey) (string, error) {
	hash := sha256.Sum256(publicKey)
	converted, err := bech32.ConvertBits(hash[:20], 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits for Bech32 address: %v", err)
	}
	bech32Address, err := bech32.Encode("tl1", converted)
	if err != nil {
		return "", fmt.Errorf("failed to encode Bech32 address: %v", err)
	}
	return bech32Address, nil
}

func (bc *Blockchain) EnsureTestValidatorRegistered(address string, publicKey ed25519.PublicKey) error {
	// Check if the validator is already registered
	_, err := bc.RetrievePublicKey(address)
	if err == nil {
		// Validator is already registered
		return nil
	}

	// Register the validator
	pubKeyBase64 := base64.StdEncoding.EncodeToString(publicKey)
	err = bc.RegisterValidator(address, pubKeyBase64, true)
	if err != nil {
		return fmt.Errorf("failed to register test validator: %v", err)
	}

	log.Printf("Registered test validator: %s", address)
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

type Validator struct {
	Address          string
	Stake            int64
	NewlyRegistered  bool
	RegistrationTime time.Time
}

func (bc *Blockchain) UpdateActiveValidators(count int) error {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	if count < 1 {
		count = 1
	}

	// Sort stakeholders by stake
	stakeholders := make([]struct {
		address string
		stake   int64
	}, 0, len(bc.Stakeholders))
	for address, stake := range bc.Stakeholders {
		stakeholders = append(stakeholders, struct {
			address string
			stake   int64
		}{address, stake})
	}
	sort.Slice(stakeholders, func(i, j int) bool {
		return stakeholders[i].stake > stakeholders[j].stake
	})

	// Select top 'count' stakeholders as active validators
	bc.ActiveValidators = make([]string, 0, count)
	for i := 0; i < count && i < len(stakeholders); i++ {
		bc.ActiveValidators = append(bc.ActiveValidators, stakeholders[i].address)
	}

	// If we don't have enough validators, generate new ones
	for len(bc.ActiveValidators) < count {
		newAddress, err := bc.GenerateAndStoreValidatorKey()
		if err != nil {
			return fmt.Errorf("failed to generate new validator: %v", err)
		}
		bc.ActiveValidators = append(bc.ActiveValidators, newAddress)
	}

	log.Printf("Updated active validators. Total: %d", len(bc.ActiveValidators))
	return nil
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

	err = bc.RegisterValidator(address, pubKeyBase64, true)
	if err != nil {
		return "", fmt.Errorf("failed to register validator: %v", err)
	}

	err = bc.StoreValidatorPrivateKey(address, priv)
	if err != nil {
		return "", fmt.Errorf("failed to store validator private key: %v", err)
	}

	return address, nil
}

// For generating multiple Validator Keys if necessary
func (bc *Blockchain) GenerateAndStoreValidatorKeys(count int) ([]string, error) {
	log.Printf("Starting to generate and store %d validator keys", count)
	validatorAddresses := make([]string, 0, count)

	for i := 0; i < count; i++ {
		log.Printf("Generating validator key %d of %d", i+1, count)
		address, err := bc.GenerateAndStoreValidatorKey()
		if err != nil {
			log.Printf("Failed to generate and store validator key %d: %v", i+1, err)
			return validatorAddresses, err
		}
		log.Printf("Successfully generated and stored validator key %d: %s", i+1, address)
		validatorAddresses = append(validatorAddresses, address)

		// Verify the key was stored correctly
		publicKey, err := bc.Database.RetrieveValidatorPublicKey(address)
		if err != nil {
			log.Printf("Error retrieving validator public key immediately after storage: %v", err)
			return validatorAddresses, fmt.Errorf("failed to verify stored validator key: %v", err)
		}

		// Check if the retrieved public key is valid
		if len(publicKey) != ed25519.PublicKeySize {
			log.Printf("Retrieved public key for address %s has incorrect size. Expected %d, got %d", address, ed25519.PublicKeySize, len(publicKey))
			return validatorAddresses, fmt.Errorf("invalid public key size for address %s", address)
		}

		log.Printf("Successfully verified stored validator public key for address: %s (Key size: %d bytes)", address, len(publicKey))

		// Add the verified key to the PublicKeyMap
		bc.PublicKeyMap[address] = publicKey
	}

	log.Printf("Finished generating and storing %d validator keys", len(validatorAddresses))
	return validatorAddresses, nil
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
func (bc *Blockchain) AddBlock(transactions []*thrylos.Transaction, validator string, prevHash []byte, optionalTimestamp ...int64) (bool, error) {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	// Handle potential forks.
	if len(bc.Blocks) > 0 && !bytes.Equal(prevHash, bc.Blocks[len(bc.Blocks)-1].Hash) {
		var selectedFork *Fork
		for _, fork := range bc.Forks {
			if bytes.Equal(fork.Blocks[len(fork.Blocks)-1].Hash, prevHash) {
				selectedFork = fork
				break
			}
		}

		// Create unsigned block for the fork
		unsignedBlock, err := bc.CreateUnsignedBlock(transactions, validator)
		if err != nil {
			return false, fmt.Errorf("failed to create unsigned block: %v", err)
		}

		// Simulate validator signing
		signedBlock, err := bc.SimulateValidatorSigning(unsignedBlock)
		if err != nil {
			return false, fmt.Errorf("failed to simulate block signing: %v", err)
		}

		// Verify the signed block
		if err := bc.VerifySignedBlock(signedBlock); err != nil {
			return false, fmt.Errorf("invalid signed block: %v", err)
		}

		blockData, err := json.Marshal(signedBlock)
		if err != nil {
			return false, fmt.Errorf("failed to serialize new block: %v", err)
		}

		blockNumber := len(bc.Blocks)
		if selectedFork != nil {
			selectedFork.Blocks = append(selectedFork.Blocks, signedBlock)
			blockNumber = len(selectedFork.Blocks) - 1
		} else {
			bc.Blocks = append(bc.Blocks, signedBlock)
			blockNumber = len(bc.Blocks) - 1
		}

		if err := bc.Database.StoreBlock(blockData, blockNumber); err != nil {
			return false, fmt.Errorf("failed to store block in database: %v", err)
		}

		return true, nil
	}

	// Verify transactions.
	for _, tx := range transactions {
		isValid, err := bc.VerifyTransaction(tx)
		if err != nil || !isValid {
			return false, fmt.Errorf("transaction verification failed: %s, error: %v", tx.GetId(), err)
		}
	}

	// Create unsigned block
	unsignedBlock, err := bc.CreateUnsignedBlock(transactions, validator)
	if err != nil {
		return false, fmt.Errorf("failed to create unsigned block: %v", err)
	}

	// Simulate validator signing
	signedBlock, err := bc.SimulateValidatorSigning(unsignedBlock)
	if err != nil {
		return false, fmt.Errorf("failed to simulate block signing: %v", err)
	}

	// Verify the signed block
	if err := bc.VerifySignedBlock(signedBlock); err != nil {
		return false, fmt.Errorf("invalid signed block: %v", err)
	}

	// Update UTXO set
	for _, tx := range signedBlock.Transactions {
		// Remove spent UTXOs
		for _, input := range tx.GetInputs() {
			utxoKey := fmt.Sprintf("%s:%d", input.GetTransactionId(), input.GetIndex())
			delete(bc.UTXOs, utxoKey)
		}
		// Add new UTXOs
		for index, output := range tx.GetOutputs() {
			utxoKey := fmt.Sprintf("%s:%d", tx.GetId(), index)
			bc.UTXOs[utxoKey] = []*thrylos.UTXO{output}
		}
	}

	// Serialize and store the block
	blockData, err := json.Marshal(signedBlock)
	if err != nil {
		return false, fmt.Errorf("failed to serialize new block: %v", err)
	}

	blockNumber := len(bc.Blocks)
	if err := bc.Database.StoreBlock(blockData, blockNumber); err != nil {
		return false, fmt.Errorf("failed to store block in database: %v", err)
	}

	// Update the blockchain with the new block
	bc.Blocks = append(bc.Blocks, signedBlock)
	bc.lastTimestamp = signedBlock.Timestamp

	if bc.OnNewBlock != nil {
		bc.OnNewBlock(signedBlock)
	}

	// Update balances for affected addresses
	bc.updateBalancesForBlock(signedBlock)

	return true, nil
}

func (bc *Blockchain) updateBalancesForBlock(block *Block) {
	for _, tx := range block.Transactions {
		// Update sender's balance
		senderBalance, _ := bc.GetBalance(tx.Sender)
		bc.Stakeholders[tx.Sender] = senderBalance // directly use int64 value

		// Update recipients' balances
		for _, output := range tx.Outputs {
			recipientBalance, _ := bc.GetBalance(output.OwnerAddress)
			bc.Stakeholders[output.OwnerAddress] = recipientBalance // directly use int64 value
		}
	}
}

// RewardValidator rewards the validator with new tokens
func (bc *Blockchain) RewardValidator(validator string, reward int64) {
	bc.Mu.Lock()
	defer bc.Mu.Unlock()

	// Deduct reward from Genesis account
	bc.Stakeholders[bc.GenesisAccount] -= reward
	// Add reward to validator
	bc.Stakeholders[validator] += reward
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

		if !bytes.Equal(currentBlock.PrevHash, prevBlock.Hash) {
			fmt.Printf("Invalid previous hash in block %d. Expected %x, got %x\n",
				currentBlock.Index, prevBlock.Hash, currentBlock.PrevHash)
			return false
		}

		computedHash := currentBlock.ComputeHash()
		if !bytes.Equal(currentBlock.Hash, computedHash) {
			fmt.Printf("Invalid hash in block %d. Expected %x, got %x\n",
				currentBlock.Index, computedHash, currentBlock.Hash)
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
