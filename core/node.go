package core

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/state"

	"github.com/joho/godotenv"
)

// Node defines a blockchain node with its properties and capabilities within the network. It represents both
// a ledger keeper and a participant in the blockchain's consensus mechanism. Each node maintains a copy of
// the blockcFetchGasEstimatehain, a list of peers, a shard reference, and a pool of pending transactions to be included in future blocks.
type Node struct {
	Address             string              // Network address of the node.
	Blockchain          *Blockchain         // The blockchain maintained by this node.
	StateManager        *state.StateManager // Replace Shard field
	PendingTransactions []*thrylos.Transaction
	PublicKeyMap        map[string]mldsa44.PublicKey // Updated to store mldsa44 public keys
	chainID             string
	ResponsibleUTXOs    map[string]shared.UTXO // Tracks UTXOs for which the node is responsible
	// Database provides an abstraction over the underlying database technology used to persist
	// blockchain data, facilitating operations like adding blocks and retrieving blockchain state
	Database       shared.BlockchainDBInterface // Updated the type to interface
	GasEstimateURL string                       // New field to store the URL for gas estimation
	// Mu provides concurrency control to ensure that operations on the blockchain are thread-safe,
	// preventing race conditions and ensuring data integrity.
	Mu                   sync.RWMutex
	WebSocketConnections map[string]*WebSocketConnection
	WebSocketMutex       sync.RWMutex
	balanceUpdateQueue   *BalanceUpdateQueue
	blockProducer        *ModernBlockProducer
	stakingService       *StakingService
	serverHost           string
	useSSL               bool
	ModernProcessor      *ModernProcessor
	BlockTrigger         chan struct{}
	DAGManager           *DAGManager
	Peers                map[string]*PeerConnection
	PeerMu               sync.RWMutex
	MaxInbound           int
	MaxOutbound          int
	txStatusMap          sync.Map
}

// Hold the chain ID and then proviude a method to set it
func (n *Node) SetChainID(chainID string) {
	n.chainID = chainID
}

func loadEnv() (map[string]string, error) {
	env := os.Getenv("ENV")
	var envPath string
	if env == "production" {
		envPath = "../../.env.prod" // The Cert is managed through the droplet
	} else {
		envPath = "../../.env.dev" // Managed through local host
	}
	envFile, err := godotenv.Read(envPath)

	return envFile, err
}

// NewNode initializes a new Node with the given address, known peers, and shard information. It creates a new
// blockchain instance for the node and optionally discovers peers if not running in a test environment.
func NewNode(address string, knownPeers []string, dataDir string, stateManager *state.StateManager) *Node {
	// Default values for WebSocket configuration
	serverHost := address                            // Use the node's address as default server host
	useSSL := strings.HasPrefix(address, "https://") // Determine SSL based on address

	envFile, _ := loadEnv() // Dynamically load the correct environment configuration

	// Retrieve the AES key securely from an environment variable, with a fallback for tests
	aesKeyEncoded := envFile["AES_KEY_ENV_VAR"]

	log.Printf("AES Key from environment: %s", aesKeyEncoded)

	aesKey, err := base64.StdEncoding.DecodeString(aesKeyEncoded)
	if err != nil {
		log.Fatalf("Failed to decode AES key: %v", err)
	} else {
		log.Println("AES key decoded successfully")
	}

	// Retrieve the URL for gas estimation from an environment variable
	gasEstimateURL := envFile["GAS_ESTIMATE_URL"]
	if gasEstimateURL == "" {
		log.Fatal("Gas estimate URL is not set in environment variables. Please configure it before starting.")
	}

	// Assuming you have a way to get or set a default genesis account address
	genesisAccount := envFile["GENESIS_ACCOUNT"]
	if genesisAccount == "" {
		log.Fatal("Genesis account is not set in environment variables. Please configure a genesis account before starting.")
	}

	if err != nil {
		log.Fatalf("error initializing app: %v\n", err)
	}

	bc, db, err := NewBlockchainWithConfig(&BlockchainConfig{
		DataDir:           dataDir,
		AESKey:            aesKey,
		GenesisAccount:    genesisAccount,
		TestMode:          true,
		DisableBackground: false,
	})
	if err != nil {
		log.Fatalf("Failed to create new blockchain: %v", err)
	}

	// Initialize staking service with the blockchain
	stakingService := NewStakingService(bc)

	node := &Node{
		Address:              address,
		Peers:                make(map[string]*PeerConnection),
		Blockchain:           bc,
		Database:             db,
		StateManager:         stateManager,
		PublicKeyMap:         make(map[string]mldsa44.PublicKey),
		ResponsibleUTXOs:     make(map[string]shared.UTXO),
		GasEstimateURL:       gasEstimateURL,
		WebSocketConnections: make(map[string]*WebSocketConnection),
		stakingService:       stakingService,
		serverHost:           serverHost,
		useSSL:               useSSL,
		BlockTrigger:         make(chan struct{}, 1),
		MaxInbound:           30,
		MaxOutbound:          20,
	}

	node.InitializeProcessors()

	// Add known peers as outbound connections
	for _, peer := range knownPeers {
		if err := node.AddPeer(peer, false); err != nil {
			log.Printf("Failed to add known peer %s: %v", peer, err)
		}
	}

	// Initialize block producer after node is set up
	node.blockProducer = NewBlockProducer(node, bc)
	node.blockProducer.Start()

	// Set the callback function
	node.Blockchain.OnNewBlock = node.ProcessConfirmedTransactions

	// Initialize the balanceUpdateQueue
	node.balanceUpdateQueue = newBalanceUpdateQueue(node)

	// Start the balance update worker goroutine
	go node.balanceUpdateQueue.balanceUpdateWorker()

	node.DiscoverPeers()

	bc.OnTransactionProcessed = node.handleProcessedTransaction

	go node.startStakingTasks()

	return node
}

// Lifecycle methods (StartBackgroundTasks, Shutdown)

func (node *Node) Shutdown() error {
	if node.blockProducer != nil {
		node.blockProducer.Stop()
	}
	// ... other cleanup ...
	return nil
}

func (node *Node) StartBackgroundTasks() {
	tickerDiscoverPeers := time.NewTicker(10 * time.Minute)
	go func() {
		for {
			select {
			case <-tickerDiscoverPeers.C:
				node.DiscoverPeers()
			}
		}
	}()
}

func (node *Node) startStakingTasks() {
	ticker := time.NewTicker(24 * time.Hour)
	for {
		select {
		case <-ticker.C:
			if err := node.stakingService.DistributeRewards(); err != nil {
				log.Printf("Error distributing staking rewards: %v", err)
			}
		}
	}
}

// These methods are correct as they simply proxy the calls
func (node *Node) GetStakingStats() map[string]interface{} {
	return node.stakingService.GetPoolStats()
}

func (node *Node) CreateStake(userAddress string, amount int64) (*Stake, error) {
	return node.stakingService.CreateStake(userAddress, amount)
}

// This method should be aligned with how we're handling stake determinations
func (node *Node) UnstakeTokens(userAddress string, isDelegator bool, amount int64) error {
	// We should determine if it's a delegator by checking validator status
	isValidator := node.stakingService.isValidator(userAddress)
	isDelegator = !isValidator

	txType := "unstake"
	if isDelegator {
		txType = "undelegate"
	}

	txID := fmt.Sprintf("%s-%s-%d", txType, userAddress, time.Now().UnixNano())
	timestamp := time.Now().Unix()

	unstakingTx := &thrylos.Transaction{
		Id:        txID,
		Sender:    "staking_pool",
		Timestamp: timestamp,
		Outputs: []*thrylos.UTXO{{
			OwnerAddress:  userAddress,
			Amount:        amount,
			Index:         0,
			TransactionId: "",
		}},
	}

	if err := node.Blockchain.AddPendingTransaction(unstakingTx); err != nil {
		return fmt.Errorf("failed to create unstaking transaction: %v", err)
	}

	return node.stakingService.unstakeTokensInternal(userAddress, isDelegator, amount, timestamp)
}

// These delegation-specific methods are correct
func (node *Node) DelegateToPool(delegator string, amount int64) (*Stake, error) {
	return node.stakingService.CreateStake(delegator, amount)
}

func (node *Node) UndelegateFromPool(delegator string, amount int64) error {
	return node.UnstakeTokens(delegator, true, amount)
}
