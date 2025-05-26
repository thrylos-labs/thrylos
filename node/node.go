package node

import (
	"log"
	"sync"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44" // Import peer for peer.ID if Node needs to interact with them
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/balance"
	"github.com/thrylos-labs/thrylos/consensus/processor"
	"github.com/thrylos-labs/thrylos/consensus/selection"
	"github.com/thrylos-labs/thrylos/consensus/staking"
	"github.com/thrylos-labs/thrylos/consensus/validator"
	"github.com/thrylos-labs/thrylos/network" // Your updated network package
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/types"
	// "google.golang.org/grpc/balancer/grpclb/state" // This import seems unrelated and unused. Consider removing if it causes issues.
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
	store *types.Store // Additional store interface if needed
	// state *state.State // State management - Removed as it's from grpc/balancer/grpclb/state which is likely not what you want
	validator           *types.Validator           // Validator functionality
	ModernProcessor     *processor.ModernProcessor // Advanced transaction processing
	BalanceManager      *balance.Manager           // Balance tracking
	StateManager        *types.StateManager        // State synchronization
	PendingTransactions []*thrylos.Transaction     // Being replaced by txPool

	// Network and peer management - NEW: Reference to Libp2pManager
	Libp2pManager *network.Libp2pManager // <--- NEW: Reference to the libp2p network manager

	// Old WebSocket and Peer fields (will be handled by Libp2pManager and WebSocketManager)
	WebSocketConnections map[string]*network.WebSocketConnection // Keep if still exposing WS API
	WebSocketMutex       sync.RWMutex
	balanceUpdateQueue   *balance.BalanceUpdateQueue
	StakingService       *staking.StakingService

	// Voting and validation
	txStatusMap        sync.Map
	VoteCounter        *validator.VoteCounter
	ValidatorSelector  *selection.ValidatorSelector
	IsVoteCounter      bool   // Indicates if this node is the designated vote counter
	VoteCounterAddress string // Address of the designated vote counter
	Address            string // This node's own address for identification in votes
}

func (n *Node) SetBlockchain(bc *types.Blockchain) {
	n.blockchain = bc
}

func (n *Node) SetMessageChannel(ch chan types.Message) {
	n.messageCh = ch
}

// NewNode initializes a new Node. It now accepts the Libp2pManager.
func NewNode(
	nodeAddress string,
	blockchainConfig *types.BlockchainConfig,
	gasEstimateURL string,
	serverHost string,
	useSSL bool,
	libp2pManager *network.Libp2pManager,
) *Node {
	if libp2pManager == nil {
		log.Fatal("FATAL: NewNode called with nil Libp2pManager")
	}
	if blockchainConfig == nil {
		log.Fatal("FATAL: NewNode called with nil BlockchainConfig")
	}

	node := &Node{
		config:               blockchainConfig,
		PublicKeyMap:         make(map[string]mldsa44.PublicKey),
		ResponsibleUTXOs:     make(map[string]types.UTXO),
		GasEstimateURL:       gasEstimateURL,
		serverHost:           serverHost,
		useSSL:               useSSL,
		BlockTrigger:         make(chan struct{}, 1),
		messageCh:            make(chan types.Message, 1000),
		Libp2pManager:        libp2pManager,
		WebSocketConnections: make(map[string]*network.WebSocketConnection),
		WebSocketMutex:       sync.RWMutex{},
		Address:              nodeAddress,
	}

	messageBus := shared.GetMessageBus()
	messageBus.Subscribe(types.ProcessBlock, node.messageCh)
	messageBus.Subscribe(types.ValidateBlock, node.messageCh)

	// IMPORTANT: StakingService needs to be initialized.
	// It depends on the BlockchainImpl, which is set *after* NewNode returns in main.go.
	// So, you cannot initialize StakingService here directly with `node.blockchain`.
	// It should be initialized in main.go *after* `mainNode.SetBlockchain` is called,
	// and then set on `mainNode`.

	return node
}
