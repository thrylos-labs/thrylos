package types

import (
	"log"
	"sync"
	"time"

	"github.com/thrylos-labs/thrylos/amount"
)

// The message system is mainly for:

// External packages communicating with node
// Cross-package communication where needed
// Avoiding circular dependencies

// Not for:

// Internal processor operations
// Direct component method calls within the same context
// Flow control within a single processor

// MessageType represents different types of messages that can be sent
type MessageType string

// Message channel type
type MessageChannel = chan Message // Using type alias for clarity

type MessageBusInterface interface {
	Subscribe(msgType MessageType, ch chan Message) // Use chan Message directly
	Unsubscribe(msgType MessageType, ch chan Message)
	Publish(msg Message)
	Close()
}

const (
	// Balance related
	GetBalance            MessageType = "GET_BALANCE"
	GetUTXOs              MessageType = "GET_UTXOS"
	AddUTXO               MessageType = "ADD_UTXO"
	UpdateState           MessageType = "UPDATE_STATE"
	FundNewAddress        MessageType = "FUND_NEW_ADDRESS"
	GetStakeholderBalance MessageType = "GET_STAKEHOLDER_BALANCE"

	// Transaction related
	ProcessTransaction         MessageType = "PROCESS_TRANSACTION"
	GetPendingTransactionCount MessageType = "GET_PENDING_TX_COUNT"
	GetPendingTransactionBatch MessageType = "GET_PENDING_TX_BATCH"
	UpdateProcessorState       MessageType = "UPDATE_PROCESSOR_STATE"
	EstimateGas                MessageType = "ESTIMATE_GAS"

	// Validator related
	SelectValidator            MessageType = "SELECT_VALIDATOR"
	ProcessValidatorVote       MessageType = "PROCESS_VALIDATOR_VOTE"
	HasSuperMajority           MessageType = "HAS_SUPER_MAJORITY"
	GetActiveValidators        MessageType = "GET_ACTIVE_VALIDATORS"
	GetStakeholders            MessageType = "GET_STAKEHOLDERS"
	IsActiveValidator          MessageType = "IS_ACTIVE_VALIDATOR"
	ProcessPendingTransactions MessageType = "PROCESS_PENDING_TRANSACTIONS"
	ConfirmBlock               MessageType = "CONFIRM_BLOCK"

	// Block related
	ProcessBlock      MessageType = "PROCESS_BLOCK"
	ValidateBlock     MessageType = "VALIDATE_BLOCK"
	HasBlock          MessageType = "HAS_BLOCK"
	GetConsensusTime  MessageType = "GET_CONSENSUS_TIME"
	GetPendingTxCount MessageType = "GET_PENDING_TX_COUNT"
	GetPendingTxBatch MessageType = "GET_PENDING_TX_BATCH"
	BroadcastVote     MessageType = "BROADCAST_VOTE"
	CreateBlock       MessageType = "CREATE_BLOCK"

	// DAG related
	ValidateDAGTx  MessageType = "VALIDATE_DAG_TX"
	UpdateDAGState MessageType = "UPDATE_DAG_STATE"
	GetDAGTips     MessageType = "GET_DAG_TIPS"

	// Node state related
	GetStakingStats      MessageType = "GET_STAKING_STATS"
	CreateStake          MessageType = "CREATE_STAKE"
	UpdatePeerList       MessageType = "UPDATE_PEER_LIST"
	IsCounterNode        MessageType = "IS_COUNTER_NODE"
	ValidateValidator    MessageType = "VALIDATE_VALIDATOR"
	GetPoolStats         MessageType = "GET_POOL_STATS"
	GetValidators        MessageType = "GET_VALIDATORS"
	IsValidator          MessageType = "IS_VALIDATOR"
	AddTransactionToPool MessageType = "ADD_TRANSACTION_TO_POOL"

	GetBlockchainInfo   MessageType = "GET_BLOCKCHAIN_INFO"
	GetBlocksFromHeight MessageType = "GET_BLOCKS_FROM_HEIGHT"
	ProcessVote         MessageType = "PROCESS_VOTE"
)

// Message represents a generic message in the system
type Message struct {
	Type       MessageType
	Data       interface{}
	ResponseCh chan Response
}

type Vote struct {
	ValidatorID    string    `json:"validator_id"`
	BlockNumber    int32     `json:"block_number"`
	BlockHash      string    `json:"block_hash,omitempty"`
	ValidationPass bool      `json:"validation_pass,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
	VoterNode      string    `json:"voter_node"`
}

type FundAddressRequest struct {
	Address string
	Amount  amount.Amount // Change from int64 to amount.Amount
}

// Response represents a generic response
type Response struct {
	Data  interface{}
	Error error
}

// Request types

type PendingTransactionBatchRequest struct {
	BatchSize int
}

type PendingTransactionCountResponse struct {
	Count int
	Error error
}

type PendingTransactionBatchResponse struct {
	Transactions []*Transaction
	Error        error
}

type IsCounterNodeResponse struct {
	IsCounter bool
	Error     error
}

type UTXORequest struct {
	Address string
}

type UTXOResponse struct {
	UTXOs []UTXO
	Error error
}

type AddUTXORequest struct {
	UTXO UTXO
}

type UpdateStateRequest struct {
	Address string
	Balance int64
}

type UpdateProcessorStateRequest struct {
	TransactionID string
	State         string
}

type UpdateTransactionStateRequest struct {
	TransactionID string
	State         string
}

type DAGTipsResponse struct {
	Tips  []string
	Error error
}

type UpdateDAGStateRequest struct {
	TransactionID string
	State         string
}

// MessageBus handles communication between packages
type MessageBus struct {
	subscribers map[MessageType][]chan Message
	mu          sync.RWMutex
}

// Global message bus instance
var (
	globalMessageBus *MessageBus
	once             sync.Once
)

// Subscribe adds a channel to receive messages of the specified type
func (mb *MessageBus) Subscribe(msgType MessageType, ch chan Message) {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	mb.subscribers[msgType] = append(mb.subscribers[msgType], ch)
}

// Unsubscribe removes a channel from receiving messages of the specified type
func (mb *MessageBus) Unsubscribe(msgType MessageType, ch chan Message) {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	subs := mb.subscribers[msgType]
	for i, subCh := range subs {
		if subCh == ch {
			mb.subscribers[msgType] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
}

// Publish sends a message to all subscribers of the message type
func (mb *MessageBus) Publish(msg Message) {
	mb.mu.RLock()
	subscribers := mb.subscribers[msg.Type]
	mb.mu.RUnlock()

	for _, ch := range subscribers {
		// Non-blocking send with select to avoid deadlocks
		select {
		case ch <- msg:
			// Message sent successfully
		default:
			// Channel is full or closed, log an error
			log.Printf("Warning: Unable to send message of type %s to subscriber, channel might be full or closed", msg.Type)
		}
	}
}

// Close closes all subscriber channels
func (mb *MessageBus) Close() {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	// Clear the subscribers map
	mb.subscribers = make(map[MessageType][]chan Message)
}

// GetGlobalMessageBus returns the singleton message bus instance
func GetGlobalMessageBus() MessageBusInterface {
	once.Do(func() {
		globalMessageBus = &MessageBus{
			subscribers: make(map[MessageType][]chan Message),
		}
	})
	return globalMessageBus
}
