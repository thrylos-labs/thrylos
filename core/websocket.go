package core

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	thrylos "github.com/thrylos-labs/thrylos"
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

type MessageItem struct {
	data    []byte
	retries int
	created time.Time
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

// Add a proper close handler
func (node *Node) closeWebSocket(conn *WebSocketConnection, address string) {
	if conn == nil {
		return
	}

	node.WebSocketMutex.Lock()
	defer node.WebSocketMutex.Unlock()

	// Close the websocket connection if it exists
	if conn.ws != nil {
		conn.ws.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(writeWait),
		)
		conn.ws.Close()
		conn.ws = nil
	}

	// Clean up channels
	select {
	case <-conn.done:
	default:
		close(conn.done)
	}

	select {
	case <-conn.send:
	default:
		close(conn.send)
	}

	delete(node.WebSocketConnections, address)
	log.Printf("WebSocket connection closed for address: %s", address)
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
}

func (conn *WebSocketConnection) enqueueMessage(data []byte) {
	conn.queueMutex.Lock()
	defer conn.queueMutex.Unlock()

	// Remove old messages if queue is full
	if len(conn.messageQueue) >= messageQueueSize {
		// Remove oldest messages
		conn.messageQueue = conn.messageQueue[1:]
	}

	conn.messageQueue = append(conn.messageQueue, &MessageItem{
		data:    data,
		retries: 0,
		created: time.Now(),
	})
}

func (conn *WebSocketConnection) processQueue() error {
	conn.queueMutex.Lock()
	defer conn.queueMutex.Unlock()

	if len(conn.messageQueue) == 0 {
		return nil
	}

	var remainingMessages []*MessageItem

	for _, item := range conn.messageQueue {
		if item.retries >= maxRetryAttempts {
			// Log dropped message
			log.Printf("Dropping message after %d retry attempts", maxRetryAttempts)
			continue
		}

		err := conn.ws.WriteMessage(websocket.TextMessage, item.data)
		if err != nil {
			item.retries++
			remainingMessages = append(remainingMessages, item)
			log.Printf("Failed to send message, attempt %d/%d: %v",
				item.retries, maxRetryAttempts, err)
			time.Sleep(retryDelay)
			continue
		}
	}

	conn.messageQueue = remainingMessages
	return nil
}

func NewWebSocketConnection(ws *websocket.Conn) *WebSocketConnection {
	return &WebSocketConnection{
		ws:              ws,
		send:            make(chan []byte, 256),
		reconnectCount:  0,
		lastConnectTime: time.Now(),
		isReconnecting:  false,
		done:            make(chan struct{}),
	}
}

func (conn *WebSocketConnection) close() {
	if conn.ws != nil {
		// Send close message with normal closure status
		conn.ws.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(writeWait),
		)
		conn.ws.Close()
	}

	// Clean up channels
	select {
	case <-conn.done:
	default:
		close(conn.done)
	}
}

func (node *Node) handleReconnection(address string) {
	// Add mutex lock for reading connection
	node.WebSocketMutex.RLock()
	conn, exists := node.WebSocketConnections[address]
	node.WebSocketMutex.RUnlock()

	if !exists || conn == nil {
		log.Printf("No valid connection found for address: %s", address)
		return
	}

	// Check if we're already trying to reconnect
	if conn.isReconnecting {
		log.Printf("Already attempting to reconnect for address: %s", address)
		return
	}

	if conn.reconnectCount >= maxReconnectAttempts {
		log.Printf("Max reconnection attempts reached for %s", address)
		node.closeWebSocket(conn, address)
		return
	}

	// Calculate backoff duration with exponential increase
	backoff := initialBackoff * time.Duration(1<<uint(conn.reconnectCount))
	if backoff > maxBackoff {
		backoff = maxBackoff
	}

	conn.reconnectCount++
	conn.isReconnecting = true

	log.Printf("Attempting to reconnect to %s in %v (attempt %d/%d)",
		address, backoff, conn.reconnectCount, maxReconnectAttempts)

	time.Sleep(backoff)

	// Attempt to establish new connection
	if err := node.reestablishConnection(address); err != nil {
		log.Printf("Reconnection failed for %s: %v", address, err)
		// Reset isReconnecting flag before attempting again
		conn.isReconnecting = false
		go node.handleReconnection(address)
	} else {
		conn.reconnectCount = 0
		conn.isReconnecting = false
		conn.lastConnectTime = time.Now()
	}
}

func (node *Node) reestablishConnection(address string) error {
	node.WebSocketMutex.Lock()
	defer node.WebSocketMutex.Unlock()

	conn, exists := node.WebSocketConnections[address]
	if !exists {
		return fmt.Errorf("no connection found for address: %s", address)
	}

	// Ensure old connection is properly closed
	if conn.ws != nil {
		conn.close()
	}

	// Create a new WebSocket connection
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		Subprotocols:     []string{"thrylos-protocol"},
	}

	// Create request header
	header := http.Header{}
	header.Add("Origin", "http://localhost:3000")
	header.Add("Sec-WebSocket-Protocol", "thrylos-protocol")

	wsURL := fmt.Sprintf("ws://%s/ws/balance?address=%s", node.serverHost, address)
	ws, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return fmt.Errorf("failed to establish WebSocket connection: %v", err)
	}

	// Create new connection instance
	newConn := NewWebSocketConnection(ws)
	node.WebSocketConnections[address] = newConn

	// Start new pumps
	go node.writePump(newConn, address)
	go node.readPump(newConn, address)

	return nil
}

// Configure the upgrader
var upgrader = websocket.Upgrader{
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
}

func (node *Node) WebSocketBalanceHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received WebSocket connection request for balance updates")

	address := r.URL.Query().Get("address")
	if address == "" {
		log.Println("Blockchain address is required")
		http.Error(w, "Blockchain address is required", http.StatusBadRequest)
		return
	}

	// Upgrade connection with error handling
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket: %v", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusInternalServerError)
		return
	}

	node.WebSocketMutex.Lock()
	// Clean up existing connection if it exists
	if existingConn, exists := node.WebSocketConnections[address]; exists {
		if existingConn != nil {
			close(existingConn.done)
			if existingConn.ws != nil {
				existingConn.ws.Close()
			}
		}
		delete(node.WebSocketConnections, address)
	}

	// Create new connection
	conn := NewWebSocketConnection(ws)
	node.WebSocketConnections[address] = conn
	node.WebSocketMutex.Unlock()

	// Start the read/write pumps
	go node.writePump(conn, address)
	go node.readPump(conn, address)

	// Send initial balance update with error handling
	if err := node.SendBalanceUpdate(address); err != nil {
		log.Printf("Error sending initial balance update for address %s: %v", address, err)
	}
}

func (node *Node) writePump(conn *WebSocketConnection, address string) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		if !conn.isReconnecting {
			// Gracefully close before reconnecting
			conn.close()
			go node.handleReconnection(address)
		}
	}()

	for {
		select {
		case <-conn.done:
			return
		case message, ok := <-conn.send:
			if !ok {
				return
			}

			if err := conn.ws.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("Write error for %s: %v", address, err)
				return
			}

		case <-ticker.C:
			if err := conn.ws.WriteControl(
				websocket.PingMessage,
				[]byte{},
				time.Now().Add(writeWait),
			); err != nil {
				log.Printf("Ping error for %s: %v", address, err)
				return
			}
		}
	}
}

func (node *Node) readPump(conn *WebSocketConnection, address string) {
	defer func() {
		node.WebSocketMutex.Lock()
		delete(node.WebSocketConnections, address)
		node.WebSocketMutex.Unlock()
		conn.ws.Close()
	}()

	conn.ws.SetReadLimit(maxMessageSize)
	conn.ws.SetReadDeadline(time.Now().Add(pongWait))
	conn.ws.SetPongHandler(func(string) error {
		conn.ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := conn.ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Process message if needed
		log.Printf("Received message from %s: %s", address, string(message))
	}
}

func (node *Node) HandleBlockchainEvent(address string) {
	node.WebSocketMutex.RLock()
	_, exists := node.WebSocketConnections[address]
	node.WebSocketMutex.RUnlock()

	if exists {
		if err := node.SendBalanceUpdate(address); err != nil {
			log.Printf("Error sending balance update for address %s: %v", address, err)
		} else {
			log.Printf("Balance update sent for address %s", address)
		}
	}
}

// SendBalanceUpdate sends a balance update through the websocket
func (node *Node) SendBalanceUpdate(address string) error {
	node.WebSocketMutex.RLock()
	conn, exists := node.WebSocketConnections[address]
	node.WebSocketMutex.RUnlock()

	if !exists {
		return fmt.Errorf("no WebSocket connection found for address: %s", address)
	}

	balance, err := node.GetBalance(address)
	if err != nil {
		return fmt.Errorf("failed to fetch balance: %v", err)
	}

	balanceThrylos := float64(balance) / 1e7

	message := map[string]interface{}{
		"blockchainAddress": address,
		"balance":           balance,
		"balanceThrylos":    balanceThrylos,
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	conn.enqueueMessage(messageBytes)
	return conn.processQueue()
}

func (node *Node) notifyBalanceUpdate(address string, balance int64) {
	node.WebSocketMutex.RLock()
	conn, exists := node.WebSocketConnections[address]
	node.WebSocketMutex.RUnlock()

	if !exists || conn == nil {
		log.Printf("Address %s is offline - balance update will be received when they reconnect", address)
		return
	}

	balanceMsg := &thrylos.BalanceMessage{
		BlockchainAddress: address,
		Balance:           balance,
		BalanceThrylos:    float64(balance) / 1e7,
	}

	msgBytes, err := json.Marshal(balanceMsg)
	if err != nil {
		log.Printf("Error marshaling balance message for %s: %v", address, err)
		return
	}

	select {
	case conn.send <- msgBytes:
		log.Printf("Successfully sent balance update for %s: %d nanoTHRYLOS (%.7f THRYLOS)",
			address, balance, balanceMsg.BalanceThrylos)
	default:
		log.Printf("Channel full or closed for %s - balance update skipped", address)
	}
}

// Add the status endpoint handler
func (node *Node) WebSocketStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	address := r.URL.Query().Get("address")
	if address == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Address parameter is required",
		})
		return
	}

	node.WebSocketMutex.RLock()
	conn, exists := node.WebSocketConnections[address]
	node.WebSocketMutex.RUnlock()

	// Get current balance
	balance, err := node.GetBalance(address)
	if err != nil {
		log.Printf("Error getting balance for %s: %v", address, err)
		balance = 0
	}

	balanceThrylos := float64(balance) / 1e7

	status := struct {
		Connected      bool      `json:"connected"`
		LastConnected  time.Time `json:"lastConnected"`
		ReconnectCount int       `json:"reconnectCount"`
		QueueSize      int       `json:"queueSize"`
		IsReconnecting bool      `json:"isReconnecting"`
		Balance        int64     `json:"balance"`
		BalanceThrylos float64   `json:"balanceThrylos"`
	}{
		Connected:      exists && conn != nil && conn.ws != nil,
		LastConnected:  time.Now(),
		ReconnectCount: 0,
		QueueSize:      0,
		IsReconnecting: false,
		Balance:        balance,
		BalanceThrylos: balanceThrylos,
	}

	if exists && conn != nil {
		status.ReconnectCount = conn.reconnectCount
		status.IsReconnecting = conn.isReconnecting
		status.LastConnected = conn.lastConnectTime
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("Error encoding status response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
