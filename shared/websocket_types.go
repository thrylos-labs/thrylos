package shared

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512

	// Maximum number of reconnection attempts
	maxReconnectAttempts = 5

	// Initial backoff delay
	initialBackoff = 1 * time.Second

	// Maximum backoff delay
	maxBackoff = 30 * time.Second

	maxRetryAttempts = 3
	retryDelay       = 500 * time.Millisecond
	messageQueueSize = 100
)

type WebSocketManager struct {
	connections map[string]*WebSocketConnection
	mutex       sync.RWMutex
	upgrader    websocket.Upgrader
	messageCh   chan Message
}

func NewWebSocketManager() *WebSocketManager {
	manager := &WebSocketManager{
		connections: make(map[string]*WebSocketConnection),
		messageCh:   make(chan Message, 100),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				allowedOrigins := []string{"http://localhost:3000", "https://node.thrylos.org"}
				for _, allowedOrigin := range allowedOrigins {
					if origin == allowedOrigin {
						return true
					}
				}
				return false
			},
		},
	}

	// Subscribe to relevant message types
	messageBus := GetMessageBus()
	messageBus.Subscribe(GetBalance, manager.messageCh)
	messageBus.Subscribe(GetUTXOs, manager.messageCh)

	go manager.handleMessages()

	return manager
}

func (m *WebSocketManager) handleMessages() {
	for msg := range m.messageCh {
		switch msg.Type {
		case GetBalance:
			request := msg.Data.(UTXORequest)
			m.handleBalanceRequest(request, msg.ResponseCh)

		case GetUTXOs:
			request := msg.Data.(UTXORequest)
			m.handleUTXORequest(request, msg.ResponseCh)
		}
	}
}

func (m *WebSocketManager) handleBalanceRequest(request UTXORequest, responseCh chan Response) {
	m.mutex.RLock()
	conn, exists := m.connections[request.Address]
	m.mutex.RUnlock()

	if !exists || conn == nil {
		responseCh <- Response{Error: fmt.Errorf("no connection found for address")}
		return
	}

	responseCh <- Response{Data: request.Address}
}

func (m *WebSocketManager) handleUTXORequest(request UTXORequest, responseCh chan Response) {
	m.mutex.RLock()
	conn, exists := m.connections[request.Address]
	m.mutex.RUnlock()

	if !exists || conn == nil {
		responseCh <- Response{Error: fmt.Errorf("no connection found for address")}
		return
	}

	responseCh <- Response{Data: request.Address}
}

type MessageItem struct {
	data    []byte
	retries int
	created time.Time
}

type Subscription struct {
	Type      string                 `json:"type"`
	Addresses []string               `json:"addresses,omitempty"`
	Options   map[string]interface{} `json:"options,omitempty"`
}

// Add ConnectionStatus struct
type ConnectionStatus struct {
	Address         string    `json:"address"`
	Connected       bool      `json:"connected"`
	LastConnected   time.Time `json:"lastConnected"`
	ReconnectCount  int       `json:"reconnectCount"`
	QueueSize       int       `json:"queueSize"`
	IsReconnecting  bool      `json:"isReconnecting"`
	LastMessageSent time.Time `json:"lastMessageSent"`
}

// WebSocketConnection represents an active WebSocket connection
type WebSocketConnection struct {
	ws              *websocket.Conn
	send            chan []byte
	messageQueue    []*MessageItem
	queueMutex      sync.Mutex
	reconnectCount  int
	lastConnectTime time.Time
	isReconnecting  bool
	done            chan struct{}
	subscriptions   []*Subscription
	subscriptionID  int64
	mutex           sync.RWMutex
}
