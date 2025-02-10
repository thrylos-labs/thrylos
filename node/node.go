package node

import (
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/balance"
	"github.com/thrylos-labs/thrylos/config"
	"github.com/thrylos-labs/thrylos/consensus/processor"
	"github.com/thrylos-labs/thrylos/consensus/staking"
	"github.com/thrylos-labs/thrylos/consensus/validator"
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/state"
)

type Node struct {
	config     *config.Config
	store      *shared.Store
	state      *state.State
	txPool     *shared.TxPool
	validator  *shared.Validator
	blockchain *shared.Blockchain
	DAGManager *processor.DAGManager
	// ModernProcessor     *processor.ModernProcessor
	messageCh           chan shared.Message
	BalanceManager      *balance.Manager
	Database            shared.Store
	StateManager        *shared.StateManager
	PendingTransactions []*thrylos.Transaction
	PublicKeyMap        map[string]mldsa44.PublicKey
	chainID             string
	ResponsibleUTXOs    map[string]shared.UTXO
	GasEstimateURL      string
	Mu                  sync.RWMutex
	// WebSocketConnections map[string]*network.WebSocketConnection
	WebSocketMutex     sync.RWMutex
	balanceUpdateQueue *balance.BalanceUpdateQueue
	// blockProducer        *shared.ModernBlockProducer
	StakingService *staking.StakingService
	serverHost     string
	useSSL         bool
	BlockTrigger   chan struct{}
	// Needs to be updated with new P2P connectioon
	// Peers       map[string]*network.PeerConnection
	PeerMu      sync.RWMutex
	MaxInbound  int
	MaxOutbound int
	txStatusMap sync.Map
	VoteCounter *validator.VoteCounter
	// ValidatorSelector  *validators.ValidatorSelector
	IsVoteCounter      bool   // Indicates if this node is the designated vote counter
	VoteCounterAddress string // Address of the designated vote counter
}

// a central component that coordinates between different parts of the system.

// Node defines a blockchain node with its properties and capabilities within the network. It represents both
// a ledger keeper and a participant in the blockchain's consensus mechanism. Each node maintains a copy of
// the blockcFetchGasEstimatehain, a list of peers, a shard reference, and a pool of pending transactions to be included in future blocks.

// type Node struct {
// 	Address             string               // Network address of the node.
// 	Blockchain          *shared.Blockchain   // The blockchain maintained by this node.
// 	StateManager        *shared.StateManager // Replace Shard field
// 	PendingTransactions []*thrylos.Transaction
// 	PublicKeyMap        map[string]mldsa44.PublicKey // Updated to store mldsa44 public keys
// 	chainID             string
// 	ResponsibleUTXOs    map[string]shared.UTXO // Tracks UTXOs for which the node is responsible
// 	// Database provides an abstraction over the underlying database technology used to persist
// 	// blockchain data, facilitating operations like adding blocks and retrieving blockchain state
// 	Database       shared.Store // Updated the type to interface
// 	GasEstimateURL string       // New field to store the URL for gas estimation
// 	// Mu provides concurrency control to ensure that operations on the blockchain are thread-safe,
// 	// preventing race conditions and ensuring data integrity.
// 	Mu sync.RWMutex
// 	// WebSocketConnections map[string]*network.WebSocketConnection
// 	WebSocketMutex     sync.RWMutex
// 	balanceUpdateQueue *balance.BalanceUpdateQueue
// 	blockProducer      *chain.ModernBlockProducer
// 	StakingService     *staking.StakingService
// 	serverHost         string
// 	useSSL             bool
// 	ModernProcessor    *processor.ModernProcessor
// 	BlockTrigger       chan struct{}
// 	DAGManager         *processor.DAGManager
// 	Peers              map[string]*network.PeerConnection
// 	PeerMu             sync.RWMutex
// 	MaxInbound         int
// 	MaxOutbound        int
// 	txStatusMap        sync.Map
// 	VoteCounter        *validator.VoteCounter
// 	ValidatorSelector  *validators.ValidatorSelector
// 	IsVoteCounter      bool   // Indicates if this node is the designated vote counter
// 	VoteCounterAddress string // Address of the designated vote counter
// 	BalanceManager     *balance.Manager
// 	messageCh          chan shared.Message
// }

// // NewNode initializes a new Node with the given address, known peers, and shard information. It creates a new
// // blockchain instance for the node and optionally discovers peers if not running in a test environment.
// func NewNode(address string, knownPeers []string, dataDir string, stateManager *state.StateManager) *Node {
// 	// Default values for WebSocket configuration
// 	serverHost := address                            // Use the node's address as default server host
// 	useSSL := strings.HasPrefix(address, "https://") // Determine SSL based on address

// 	envFile, _ := loadEnv() // Dynamically load the correct environment configuration

// 	// Retrieve the AES key securely from an environment variable, with a fallback for tests
// 	aesKeyEncoded := envFile["AES_KEY_ENV_VAR"]

// 	log.Printf("AES Key from environment: %s", aesKeyEncoded)

// 	aesKey, err := base64.StdEncoding.DecodeString(aesKeyEncoded)
// 	if err != nil {
// 		log.Fatalf("Failed to decode AES key: %v", err)
// 	} else {
// 		log.Println("AES key decoded successfully")
// 	}

// 	// Retrieve the URL for gas estimation from an environment variable
// 	gasEstimateURL := envFile["GAS_ESTIMATE_URL"]
// 	if gasEstimateURL == "" {
// 		log.Fatal("Gas estimate URL is not set in environment variables. Please configure it before starting.")
// 	}

// 	// Assuming you have a way to get or set a default genesis account address
// 	genesisAccount := envFile["GENESIS_ACCOUNT"]
// 	if genesisAccount == "" {
// 		log.Fatal("Genesis account is not set in environment variables. Please configure a genesis account before starting.")
// 	}

// 	if err != nil {
// 		log.Fatalf("error initializing app: %v\n", err)
// 	}

// 	bc, db, err := chain.NewBlockchainWithConfig(&chain.BlockchainConfig{
// 		DataDir:           dataDir,
// 		AESKey:            aesKey,
// 		GenesisAccount:    genesisAccount,
// 		TestMode:          true,
// 		DisableBackground: false,
// 	})
// 	if err != nil {
// 		log.Fatalf("Failed to create new blockchain: %v", err)
// 	}

// 	// Initialize staking service with the blockchain
// 	stakingService := staking.NewStakingService(bc)

// 	node := &Node{
// 		Address:              address,
// 		Peers:                make(map[string]*network.PeerConnection),
// 		Blockchain:           bc,
// 		Database:             db,
// 		StateManager:         stateManager,
// 		PublicKeyMap:         make(map[string]mldsa44.PublicKey),
// 		ResponsibleUTXOs:     make(map[string]shared.UTXO),
// 		GasEstimateURL:       gasEstimateURL,
// 		WebSocketConnections: make(map[string]*network.WebSocketConnection),
// 		StakingService:       stakingService,
// 		serverHost:           serverHost,
// 		useSSL:               useSSL,
// 		BlockTrigger:         make(chan struct{}, 1),
// 		MaxInbound:           30,
// 		MaxOutbound:          20,
// 		messageCh:            make(chan shared.Message, 1000),
// 	}

// 	// Subscribe to message types
// 	messageBus := shared.GetMessageBus()
// 	messageBus.Subscribe(shared.GetBalance, node.messageCh)
// 	messageBus.Subscribe(shared.ProcessBlock, node.messageCh)
// 	messageBus.Subscribe(shared.ValidateBlock, node.messageCh)
// 	messageBus.Subscribe(shared.UpdatePeerList, node.messageCh)
// 	messageBus.Subscribe(shared.GetStakingStats, node.messageCh)
// 	messageBus.Subscribe(shared.CreateStake, node.messageCh)

// 	// Start message handler
// 	go node.handleMessages()

// 	wsManager := network.NewWebSocketManager(node)
// 	node.BalanceManager = balance.NewManager(node, wsManager)

// 	isDesignatedCounter := false
// 	if len(bc.GetActiveValidators()) > 0 {
// 		// Make the first validator the designated counter
// 		isDesignatedCounter = (address == bc.GetActiveValidators()[0])
// 	}

// 	// Initialize VoteCounter with designation status
// 	node.VoteCounter = validator.NewVoteCounter(node, isDesignatedCounter)

// 	if isDesignatedCounter {
// 		log.Printf("Node %s designated as vote counter", address)
// 	}
// 	// Initialize ValidatorSelector with node
// 	node.ValidatorSelector = validators.NewValidatorSelector(bc, node)

// 	node.InitializeProcessors()

// 	// Add known peers as outbound connections
// 	for _, peer := range knownPeers {
// 		if err := network.AddPeer(peer, false); err != nil {
// 			log.Printf("Failed to add known peer %s: %v", peer, err)
// 		}
// 	}

// 	// Initialize block producer after node is set up
// 	node.blockProducer = chain.NewBlockProducer(node, bc)
// 	node.blockProducer.Start()

// 	// Set the callback function
// 	node.Blockchain.OnNewBlock = balance.ProcessConfirmedTransactions

// 	// Initialize the balanceUpdateQueue
// 	node.balanceUpdateQueue = balance.newBalanceUpdateQueue(node)

// 	// Start the balance update worker goroutine
// 	go node.balanceUpdateQueue.balanceUpdateWorker()

// 	network.DiscoverPeers()

// 	bc.OnTransactionProcessed = balance.handleProcessedTransaction

// 	go node.startStakingTasks()

// 	return node
// }
