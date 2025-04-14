package network

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/thrylos-labs/thrylos/types"
)

// Constants for WebSocket configuration
const (
	WriteWait            = 10 * time.Second
	PingPeriod           = 30 * time.Second
	PongWait             = 60 * time.Second
	MaxMessageSize       = 512
	MaxReconnectAttempts = 5
	InitialBackoff       = 1 * time.Second
	MaxBackoff           = 1 * time.Minute
	MessageQueueSize     = 100
)

// WebSocketConnection represents an active WebSocket connection
type WebSocketConnection struct {
	ws              *websocket.Conn
	send            chan []byte
	messageQueue    []*types.MessageItem
	queueMutex      sync.Mutex
	reconnectCount  int
	lastConnectTime time.Time
	isReconnecting  bool
	done            chan struct{}
	subscriptions   []*types.Subscription
	subscriptionID  int64
	mutex           sync.RWMutex
}

// WebSocketManager manages WebSocket connections
type WebSocketManager struct {
	connections map[string]*WebSocketConnection
	mutex       sync.RWMutex
	upgrader    websocket.Upgrader
	messageCh   types.MessageChannel
	messageBus  types.MessageBusInterface
}

// NewWebSocketManager initializes a WebSocket manager
func NewWebSocketManager(messageBus types.MessageBusInterface) *WebSocketManager {
	manager := &WebSocketManager{
		connections: make(map[string]*WebSocketConnection),
		messageCh:   make(types.MessageChannel, 100),
		messageBus:  messageBus,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // Adjust for production security
			},
		},
	}

	// Subscribe to relevant message types
	messageBus.Subscribe(types.GetBalance, manager.messageCh)
	messageBus.Subscribe(types.ProcessTransaction, manager.messageCh)
	messageBus.Subscribe(types.ProcessBlock, manager.messageCh)

	go manager.handleMessages()

	return manager
}

// handleMessages processes incoming messages from the message bus
func (m *WebSocketManager) handleMessages() {
	for msg := range m.messageCh {
		switch msg.Type {
		case types.GetBalance:
			if req, ok := msg.Data.(types.UTXORequest); ok {
				m.handleBalanceRequest(req, msg.ResponseCh)
			}
		case types.GetUTXOs:
			if req, ok := msg.Data.(types.UTXORequest); ok {
				m.handleUTXORequest(req, msg.ResponseCh)
			}
		case types.ProcessTransaction, types.ProcessBlock:
			// Notify subscribed clients
			m.notifySubscribers(msg)
		}
	}
}

func (m *WebSocketManager) handleBalanceRequest(request types.UTXORequest, responseCh chan types.Response) {
	m.mutex.RLock()
	conn, exists := m.connections[request.Address]
	m.mutex.RUnlock()

	if !exists || conn == nil {
		responseCh <- types.Response{Error: fmt.Errorf("no connection for address: %s", request.Address)}
		return
	}

	// Placeholder: Fetch balance via message bus if needed
	responseCh <- types.Response{Data: int64(0)} // Replace with actual balance
}

func (m *WebSocketManager) handleUTXORequest(request types.UTXORequest, responseCh chan types.Response) {
	m.mutex.RLock()
	conn, exists := m.connections[request.Address]
	m.mutex.RUnlock()

	if !exists || conn == nil {
		responseCh <- types.Response{Error: fmt.Errorf("no connection for address: %s", request.Address)}
		return
	}

	// Placeholder: Fetch UTXOs via message bus if needed
	responseCh <- types.Response{Data: []types.UTXO{}}
}

func (m *WebSocketManager) notifySubscribers(msg types.Message) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// for address, conn := range m.connections {
	// 	for _, sub := range conn.subscriptions {
	// 		if sub.Type == string(msg.Type) {
	// 			data, _ := json.Marshal(msg.Data)
	// 			conn.send <- data
	// 		}
	// 	}
	// }
}

// WebSocketBalanceHandler handles WebSocket connections for balance updates
func (m *WebSocketManager) WebSocketBalanceHandler(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		http.Error(w, "Address required", http.StatusBadRequest)
		return
	}

	ws, err := m.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	m.mutex.Lock()
	if conn, exists := m.connections[address]; exists {
		conn.close()
	}
	conn := NewWebSocketConnection(ws)
	m.connections[address] = conn
	m.mutex.Unlock()

	go m.writePump(conn, address)
	go m.readPump(conn, address)

	// Send initial balance
	m.SendBalanceUpdate(address)
}

// writePump handles sending messages to the client
func (m *WebSocketManager) writePump(conn *WebSocketConnection, address string) {
	ticker := time.NewTicker(PingPeriod)
	defer func() {
		ticker.Stop()
		conn.close()
		go m.handleReconnection(address)
	}()

	for {
		select {
		case <-conn.done:
			return
		case message := <-conn.send:
			conn.ws.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := conn.ws.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("Write error for %s: %v", address, err)
				return
			}
		case <-ticker.C:
			conn.ws.SetWriteDeadline(time.Now().Add(WriteWait))
			if err := conn.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("Ping error for %s: %v", address, err)
				return
			}
		}
	}
}

// readPump handles reading messages from the client
func (m *WebSocketManager) readPump(conn *WebSocketConnection, address string) {
	defer func() {
		m.closeWebSocket(conn, address)
	}()

	conn.ws.SetReadLimit(MaxMessageSize)
	conn.ws.SetReadDeadline(time.Now().Add(PongWait))
	conn.ws.SetPongHandler(func(string) error {
		conn.ws.SetReadDeadline(time.Now().Add(PongWait))
		return nil
	})

	for {
		_, message, err := conn.ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error for %s: %v", address, err)
			}
			break
		}

		// Process client messages (e.g., subscription requests)
		m.processClientMessage(address, message)
	}
}

func (m *WebSocketManager) processClientMessage(address string, message []byte) {
	var req struct {
		Type      string   `json:"type"`
		Addresses []string `json:"addresses"`
	}
	if err := json.Unmarshal(message, &req); err != nil {
		log.Printf("Invalid client message: %v", err)
		return
	}

	sub := &types.Subscription{Type: req.Type, Addresses: req.Addresses}
	switch req.Type {
	case "balance":
		m.subscribeToBalance(sub)
	case "transactions":
		m.subscribeToTransactions(sub)
	case "blocks":
		m.subscribeToBlocks(sub)
	}
}

// SendBalanceUpdate sends a balance update to the connected wallet
func (m *WebSocketManager) SendBalanceUpdate(address string) error {
	responseCh := make(chan types.Response)
	m.messageBus.Publish(types.Message{
		Type:       types.GetBalance,
		Data:       types.UTXORequest{Address: address},
		ResponseCh: responseCh,
	})

	response := <-responseCh
	if response.Error != nil {
		return response.Error
	}

	balance, ok := response.Data.(int64)
	if !ok {
		return fmt.Errorf("invalid balance data type")
	}

	notification := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "subscription",
		"params": map[string]interface{}{
			"subscription": "balance",
			"result": map[string]interface{}{
				"address":        address,
				"balance":        balance,
				"balanceThrylos": float64(balance) / 1e7,
			},
		},
	}

	messageBytes, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to marshal balance update: %v", err)
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if conn, exists := m.connections[address]; exists && conn != nil {
		select {
		case conn.send <- messageBytes:
			return nil
		default:
			return fmt.Errorf("send channel full for %s", address)
		}
	}
	return fmt.Errorf("no connection for %s", address)
}

// subscribeToBalance adds a balance subscription
func (m *WebSocketManager) subscribeToBalance(sub *types.Subscription) {
	for _, address := range sub.Addresses {
		m.mutex.Lock()
		if conn, exists := m.connections[address]; exists {
			conn.subscriptions = append(conn.subscriptions, sub)
			m.SendBalanceUpdate(address)
		}
		m.mutex.Unlock()
	}
}

// Placeholder subscription methods
func (m *WebSocketManager) subscribeToTransactions(sub *types.Subscription) {
	// Implement transaction subscription logic
}

func (m *WebSocketManager) subscribeToBlocks(sub *types.Subscription) {
	// Implement block subscription logic
}

// NewWebSocketConnection creates a new WebSocket connection
func NewWebSocketConnection(ws *websocket.Conn) *WebSocketConnection {
	return &WebSocketConnection{
		ws:              ws,
		send:            make(chan []byte, 256),
		messageQueue:    make([]*types.MessageItem, 0, MessageQueueSize),
		done:            make(chan struct{}),
		subscriptions:   make([]*types.Subscription, 0),
		lastConnectTime: time.Now(),
	}
}

// closeWebSocket closes a WebSocket connection
func (m *WebSocketManager) closeWebSocket(conn *WebSocketConnection, address string) {
	if conn == nil {
		return
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	conn.close()
	delete(m.connections, address)
	log.Printf("WebSocket closed for %s", address)
}

func (conn *WebSocketConnection) close() {
	if conn.ws != nil {
		conn.ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		conn.ws.Close()
	}
	close(conn.done)
}

// handleReconnection attempts to reconnect a dropped connection
func (m *WebSocketManager) handleReconnection(address string) {
	m.mutex.RLock()
	conn, exists := m.connections[address]
	m.mutex.RUnlock()

	if !exists || conn == nil || conn.reconnectCount >= MaxReconnectAttempts {
		return
	}

	backoff := InitialBackoff * time.Duration(1<<uint(conn.reconnectCount))
	if backoff > MaxBackoff {
		backoff = MaxBackoff
	}

	conn.reconnectCount++
	conn.isReconnecting = true
	time.Sleep(backoff)

	if err := m.reestablishConnection(address); err != nil {
		go m.handleReconnection(address)
	} else {
		conn.reconnectCount = 0
		conn.isReconnecting = false
		conn.lastConnectTime = time.Now()
	}
}

func (m *WebSocketManager) reestablishConnection(address string) error {
	// Simplified for brevity; implement as needed
	return fmt.Errorf("reconnection not implemented")
}
