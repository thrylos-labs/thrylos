package node

import (
	"encoding/base64"
	"log"
	"strings"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/balance"
	"github.com/thrylos-labs/thrylos/consensus/processor"
	"github.com/thrylos-labs/thrylos/consensus/selection"
	"github.com/thrylos-labs/thrylos/consensus/staking"
	"github.com/thrylos-labs/thrylos/consensus/validator"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/types"
	"google.golang.org/grpc/balancer/grpclb/state"
)

type Node struct {
	// Essential configuration and blockchain components
	config     *types.BlockchainConfig // Changed to match actual config type
	blockchain *types.Blockchain       // Changed to match the returned type
	Database   types.Store

	// Transaction handling
	txPool     types.TxPool // Changed from pointer to interface
	DAGManager *processor.DAGManager
	messageCh  chan types.Message

	// Core state tracking
	PublicKeyMap     map[string]mldsa44.PublicKey
	ResponsibleUTXOs map[string]types.UTXO
	chainID          string

	// Basic settings
	GasEstimateURL string
	serverHost     string
	useSSL         bool

	// Essential synchronization
	Mu           sync.RWMutex
	BlockTrigger chan struct{}

	// Optional components - commented out for future implementation
	store               *types.Store               // Additional store interface if needed
	state               *state.State               // State management
	validator           *types.Validator           // Validator functionality
	ModernProcessor     *processor.ModernProcessor // Advanced transaction processing
	BalanceManager      *balance.Manager           // Balance tracking
	StateManager        *types.StateManager        // State synchronization
	PendingTransactions []*thrylos.Transaction     // Being replaced by txPool

	// Network and peer management - for future implementation
	// WebSocketConnections map[string]*network.WebSocketConnection
	WebSocketMutex     sync.RWMutex
	balanceUpdateQueue *balance.BalanceUpdateQueue
	// blockProducer        *chain.ModernBlockProducer
	StakingService *staking.StakingService
	// Peers               map[string]*network.PeerConnection
	PeerMu      sync.RWMutex
	MaxInbound  int
	MaxOutbound int

	// Voting and validation - for future implementation
	txStatusMap        sync.Map
	VoteCounter        *validator.VoteCounter
	ValidatorSelector  *selection.ValidatorSelector
	IsVoteCounter      bool   // Indicates if this node is the designated vote counter
	VoteCounterAddress string // Address of the designated vote counter
}

// NewNode initializes a new Node with the given address, known peers, and shard information. It creates a new
// blockchain instance for the node and optionally discovers peers if not running in a test environment.
func NewNode(address string, dataDir string) *Node { // removed knownPeers
	// Basic configuration
	serverHost := address
	useSSL := strings.HasPrefix(address, "https://")

	// Load environment configuration
	envFile, _ := loadEnv()

	// Get and decode AES key
	aesKeyEncoded := envFile["AES_KEY_ENV_VAR"]
	log.Printf("AES Key from environment: %s", aesKeyEncoded)

	aesKey, err := base64.StdEncoding.DecodeString(aesKeyEncoded)
	if err != nil {
		log.Fatalf("Failed to decode AES key: %v", err)
	}
	log.Println("AES key decoded successfully")

	// Get essential configuration
	gasEstimateURL := envFile["GAS_ESTIMATE_URL"]
	if gasEstimateURL == "" {
		log.Fatal("Gas estimate URL is not set in environment variables")
	}

	genesisAccount := envFile["GENESIS_ACCOUNT"]
	if genesisAccount == "" {
		log.Fatal("Genesis account is not set in environment variables")
	}

	// Generate genesis account private key
	privKey, err := crypto.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate genesis account key: %v", err)
	}

	// Initialize blockchain with minimal configuration
	blockchainConfig := &types.BlockchainConfig{
		DataDir:        dataDir,
		AESKey:         aesKey,
		GenesisAccount: privKey,
		TestMode:       true,
	}

	// bc, db, err := chain.NewBlockchain(blockchainConfig)
	// if err != nil {
	// 	log.Fatalf("Failed to create new blockchain: %v", err)
	// }

	// Create node with essential components
	node := &Node{
		config: blockchainConfig, // Use the config we created
		// blockchain:       bc.Blockchain,    // Access the embedded *types.Blockchain
		// Database:         db,               // db implements types.Store
		PublicKeyMap:     make(map[string]mldsa44.PublicKey),
		ResponsibleUTXOs: make(map[string]types.UTXO),
		GasEstimateURL:   gasEstimateURL,
		serverHost:       serverHost,
		useSSL:           useSSL,
		BlockTrigger:     make(chan struct{}, 1),
		messageCh:        make(chan types.Message, 1000),
	}

	// Subscribe to essential message types
	messageBus := shared.GetMessageBus()
	messageBus.Subscribe(types.ProcessBlock, node.messageCh)
	messageBus.Subscribe(types.ValidateBlock, node.messageCh)

	// Start essential message handler
	// go node.handleMessages()

	/* Optional components commented out for future implementation
	   // Initialize staking service
	   // stakingService := staking.NewStakingService(bc)

	   // Peer management
	   // node.Peers = make(map[string]*network.PeerConnection)
	   // node.WebSocketConnections = make(map[string]*network.WebSocketConnection)
	   // node.MaxInbound = 30
	   // node.MaxOutbound = 20

	   // WebSocket and Balance management
	   // wsManager := network.NewWebSocketManager(node)
	   // node.BalanceManager = balance.NewManager(node, wsManager)

	   // Validator components
	   // isDesignatedCounter := false
	   // if len(bc.GetActiveValidators()) > 0 {
	   //     isDesignatedCounter = (address == bc.GetActiveValidators()[0])
	   // }
	   // node.VoteCounter = validator.NewVoteCounter(node, isDesignatedCounter)
	   // node.ValidatorSelector = validators.NewValidatorSelector(bc, node)

	   // Additional initialization
	   // node.InitializeProcessors()
	   // node.blockProducer = chain.NewBlockProducer(node, bc)
	   // node.blockProducer.Start()
	   // node.balanceUpdateQueue = balance.newBalanceUpdateQueue(node)
	   // go node.balanceUpdateQueue.balanceUpdateWorker()
	   // network.DiscoverPeers()
	   // go node.startStakingTasks()
	*/

	return node
}
