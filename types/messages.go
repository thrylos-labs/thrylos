package types

import (
	"sync"

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
	GetBalance  MessageType = "GET_BALANCE"
	GetUTXOs    MessageType = "GET_UTXOS"
	AddUTXO     MessageType = "ADD_UTXO"
	UpdateState MessageType = "UPDATE_STATE"

	// Transaction related
	ProcessTransaction         MessageType = "PROCESS_TRANSACTION"
	GetPendingTransactionCount MessageType = "GET_PENDING_TX_COUNT"
	GetPendingTransactionBatch MessageType = "GET_PENDING_TX_BATCH"
	UpdateProcessorState       MessageType = "UPDATE_PROCESSOR_STATE"

	// Block related
	ProcessBlock      MessageType = "PROCESS_BLOCK"
	ValidateBlock     MessageType = "VALIDATE_BLOCK"
	HasBlock          MessageType = "HAS_BLOCK"
	GetConsensusTime  MessageType = "GET_CONSENSUS_TIME"
	GetPendingTxCount MessageType = "GET_PENDING_TX_COUNT"
	GetPendingTxBatch MessageType = "GET_PENDING_TX_BATCH"
	BroadcastVote     MessageType = "BROADCAST_VOTE"

	// DAG related
	ValidateDAGTx  MessageType = "VALIDATE_DAG_TX"
	UpdateDAGState MessageType = "UPDATE_DAG_STATE"
	GetDAGTips     MessageType = "GET_DAG_TIPS"

	// Node state related
	GetStakingStats MessageType = "GET_STAKING_STATS"
	CreateStake     MessageType = "CREATE_STAKE"
	UpdatePeerList  MessageType = "UPDATE_PEER_LIST"
	IsCounterNode   MessageType = "IS_COUNTER_NODE"
)

// Message represents a generic message in the system
type Message struct {
	Type       MessageType
	Data       interface{}
	ResponseCh chan Response
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
	Balance amount.Amount
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
