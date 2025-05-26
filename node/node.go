package node

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44" // Import peer for peer.ID if Node needs to interact with them
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/balance"
	"github.com/thrylos-labs/thrylos/consensus/processor"
	"github.com/thrylos-labs/thrylos/consensus/selection"
	"github.com/thrylos-labs/thrylos/consensus/staking"
	"github.com/thrylos-labs/thrylos/consensus/validator"
	"github.com/thrylos-labs/thrylos/network" // Your updated network package
	"github.com/thrylos-labs/thrylos/types"
	"github.com/thrylos-labs/thrylos/utils"
	// "google.golang.org/grpc/balancer/grpclb/state" // This import seems unrelated and unused. Consider removing if it causes issues.
)

type Node struct {
	// ... (existing fields) ...

	// Essential configuration and blockchain components
	config     *types.BlockchainConfig
	blockchain *types.Blockchain
	Database   types.Store

	// Transaction handling
	txPool     types.TxPool
	DAGManager *processor.DAGManager
	messageCh  chan types.Message        // This is the *receiving* channel for the Node's internal handler
	MessageBus types.MessageBusInterface // <--- NEW: Reference to the message bus

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

	// Optional components
	store               *types.Store
	validator           *types.Validator
	ModernProcessor     *processor.ModernProcessor
	BalanceManager      *balance.Manager
	StateManager        *types.StateManager
	PendingTransactions []*thrylos.Transaction

	StakingService *staking.StakingService

	// Network and peer management
	Libp2pManager        *network.Libp2pManager
	WebSocketConnections map[string]*network.WebSocketConnection
	WebSocketMutex       sync.RWMutex
	balanceUpdateQueue   *balance.BalanceUpdateQueue

	// Voting and validation
	txStatusMap        sync.Map
	VoteCounter        *validator.VoteCounter
	ValidatorSelector  *selection.ValidatorSelector
	IsVoteCounter      bool
	VoteCounterAddress string
	Address            string
}

func (n *Node) SetBlockchain(bc *types.Blockchain) {
	n.blockchain = bc
}

func (n *Node) SetMessageChannel(ch chan types.Message) {
	n.messageCh = ch
}

// NewNode initializes a new Node. It now accepts the Libp2pManager and MessageBus.
func NewNode(
	nodeAddress string,
	blockchainConfig *types.BlockchainConfig,
	gasEstimateURL string,
	serverHost string,
	useSSL bool,
	libp2pManager *network.Libp2pManager,
	messageBus types.MessageBusInterface, // <--- NEW: MessageBus parameter
) *Node {
	if libp2pManager == nil {
		log.Fatal("FATAL: NewNode called with nil Libp2pManager")
	}
	if blockchainConfig == nil {
		log.Fatal("FATAL: NewNode called with nil BlockchainConfig")
	}
	if messageBus == nil { // Validate messageBus
		log.Fatal("FATAL: NewNode called with nil MessageBus")
	}

	node := &Node{
		config:               blockchainConfig,
		PublicKeyMap:         make(map[string]mldsa44.PublicKey),
		ResponsibleUTXOs:     make(map[string]types.UTXO),
		GasEstimateURL:       gasEstimateURL,
		serverHost:           serverHost,
		useSSL:               useSSL,
		BlockTrigger:         make(chan struct{}, 1),
		messageCh:            make(chan types.Message, 1000), // Node's internal message channel
		MessageBus:           messageBus,                     // <--- Store the MessageBus
		Libp2pManager:        libp2pManager,
		WebSocketConnections: make(map[string]*network.WebSocketConnection),
		WebSocketMutex:       sync.RWMutex{},
		Address:              nodeAddress,
	}

	// Subscriptions for node.messageCh are typically done here or in a Start() method on Node
	// messageBus.Subscribe(types.ProcessBlock, node.messageCh)
	// messageBus.Subscribe(types.ValidateBlock, node.messageCh)
	// This depends on whether you have a `node.handleMessages()` func that consumes `node.messageCh`
	// For now, the existing messageBus.Subscribe in `main.go` and `connectBlockchainToMessageBus`
	// are handling the wiring.

	return node
}

func (n *Node) IsActiveValidator(address string) bool {
	respCh := make(chan types.Response)
	n.MessageBus.Publish(types.Message{ // <--- USE n.MessageBus
		Type:       types.IsActiveValidator,
		Data:       address,
		ResponseCh: respCh,
	})
	select {
	case resp := <-respCh:
		if resp.Error != nil {
			log.Printf("ERROR: Node.IsActiveValidator: %v", resp.Error)
			return false
		}
		if isActive, ok := resp.Data.(bool); ok {
			return isActive
		}
		log.Printf("WARN: Node.IsActiveValidator: Unexpected data type for IsActiveValidator: %T", resp.Data)
		return false
	case <-time.After(5 * time.Second): // Add a timeout to prevent deadlock
		log.Printf("ERROR: Node.IsActiveValidator: Timeout waiting for response.")
		return false
	}
}

// GetActiveValidators returns a list of addresses for currently active validators (queries message bus)
func (n *Node) GetActiveValidators() []string {
	respCh := make(chan types.Response)
	n.MessageBus.Publish(types.Message{ // <--- USE n.MessageBus
		Type:       types.GetActiveValidators,
		ResponseCh: respCh,
	})
	select {
	case resp := <-respCh:
		if resp.Error != nil {
			log.Printf("ERROR: Node.GetActiveValidators: %v", resp.Error)
			return []string{}
		}
		if validators, ok := resp.Data.([]string); ok {
			return validators
		}
		log.Printf("WARN: Node.GetActiveValidators: Unexpected data type for active validators: %T", resp.Data)
		return []string{}
	case <-time.After(5 * time.Second):
		log.Printf("ERROR: Node.GetActiveValidators: Timeout waiting for response.")
		return []string{}
	}
}

// ConfirmBlock is called by VoteCounter when a supermajority is reached (queries message bus)
func (n *Node) ConfirmBlock(blockNumber int32) {
	respCh := make(chan types.Response)
	n.MessageBus.Publish(types.Message{ // <--- USE n.MessageBus
		Type:       types.ConfirmBlock,
		Data:       blockNumber,
		ResponseCh: respCh,
	})
	select {
	case resp := <-respCh:
		if resp.Error != nil {
			log.Printf("ERROR: Node.ConfirmBlock: Error confirming block %d: %v", blockNumber, resp.Error)
		} else {
			log.Printf("INFO: Node sent request to confirm block %d. Response: %+v", blockNumber, resp.Data)
		}
	case <-time.After(5 * time.Second):
		log.Printf("ERROR: Node.ConfirmBlock: Timeout confirming block %d.", blockNumber)
	}
}

// --- Methods from node_stakes.go (NOW INTEGRATED HERE) ---

// UnstakeTokens handles unstaking/undelegation requests.
func (n *Node) UnstakeTokens(userAddress string, isDelegator bool, amount int64) error {
	if n.StakingService == nil { // Will be initialized in main.go and set on node
		return fmt.Errorf("StakingService is not initialized on Node")
	}
	if n.blockchain == nil || n.blockchain == nil { // Will be initialized in main.go and set on node
		return fmt.Errorf("Blockchain is not initialized on Node")
	}

	isValidator := n.StakingService.IsValidator(userAddress)
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

	responseCh := make(chan types.Response)
	n.MessageBus.Publish(types.Message{ // <--- USE n.MessageBus
		Type:       types.AddTransactionToPool,
		Data:       utils.ConvertToSharedTransaction(unstakingTx),
		ResponseCh: responseCh,
	})

	select {
	case resp := <-responseCh:
		if resp.Error != nil {
			return fmt.Errorf("failed to add unstaking transaction to pool: %w", resp.Error)
		}
		log.Printf("INFO: Unstaking/Undelegation transaction %s added to pool.", txID)
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout adding unstaking transaction to pool")
	}

	return n.StakingService.UnstakeTokensInternal(userAddress, isDelegator, amount, timestamp)
}

// GetStakingStats proxies to StakingService.GetPoolStats().
func (n *Node) GetStakingStats() map[string]interface{} {
	if n.StakingService == nil {
		log.Printf("WARN: GetStakingStats called but StakingService is nil.")
		return make(map[string]interface{})
	}
	return n.StakingService.GetPoolStats()
}

// CreateStake proxies to StakingService.CreateStake().
func (n *Node) CreateStake(userAddress string, amount int64) (*types.Stake, error) {
	if n.StakingService == nil {
		return nil, fmt.Errorf("StakingService is not initialized on Node")
	}
	return n.StakingService.CreateStake(userAddress, amount)
}

// DelegateToPool proxies to StakingService.CreateStake().
func (n *Node) DelegateToPool(delegator string, amount int64) (*types.Stake, error) {
	if n.StakingService == nil {
		return nil, fmt.Errorf("StakingService is not initialized on Node")
	}
	return n.StakingService.CreateStake(delegator, amount)
}

// UndelegateFromPool uses UnstakeTokens method.
func (n *Node) UndelegateFromPool(delegator string, amount int64) error {
	return n.UnstakeTokens(delegator, true, amount)
}

// GetStakeholders returns a map of addresses to their staked amounts.
// This is the version that queries the message bus, which is correct for decoupling.
func (n *Node) GetStakeholders() map[string]int64 {
	respCh := make(chan types.Response)
	n.MessageBus.Publish(types.Message{ // <--- USE n.MessageBus
		Type:       types.GetStakeholders,
		ResponseCh: respCh,
	})
	select {
	case resp := <-respCh:
		if resp.Error != nil {
			log.Printf("ERROR: Node.GetStakeholders: %v", resp.Error)
			return make(map[string]int64)
		}
		if stakeholders, ok := resp.Data.(map[string]int64); ok {
			return stakeholders
		}
		log.Printf("WARN: Node.GetStakeholders: Unexpected data type for stakeholders: %T", resp.Data)
		return make(map[string]int64)
	case <-time.After(5 * time.Second):
		log.Printf("ERROR: Node.GetStakeholders: Timeout waiting for response.")
		return make(map[string]int64)
	}
}
