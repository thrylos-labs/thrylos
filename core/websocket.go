package core

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
)

// WebSocketConnection represents an active WebSocket connection
type WebSocketConnection struct {
	ws   *websocket.Conn
	send chan []byte
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

// Event only web socket updates
// In WebSocketBalanceHandler
func (node *Node) WebSocketBalanceHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received WebSocket connection request for balance updates")

	// Add additional headers for WebSocket
	upgrader.CheckOrigin = func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		allowedOrigins := []string{"http://localhost:3000", "https://node.thrylos.org"}
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				return true
			}
		}
		return false
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket: %v", err)
		return
	}

	address := r.URL.Query().Get("address")
	if address == "" {
		log.Println("Blockchain address is required")
		ws.WriteMessage(websocket.TextMessage, []byte("Blockchain address is required"))
		ws.Close()
		return
	}

	// Clean up any existing connection for this address
	node.WebSocketMutex.Lock()
	if existingConn, exists := node.WebSocketConnections[address]; exists {
		existingConn.ws.Close()
		delete(node.WebSocketConnections, address)
	}
	node.WebSocketMutex.Unlock()

	// Create new connection
	conn := &WebSocketConnection{
		ws:   ws,
		send: make(chan []byte, 256),
	}

	node.WebSocketMutex.Lock()
	node.WebSocketConnections[address] = conn
	node.WebSocketMutex.Unlock()

	// Send initial balance update
	if err := node.SendBalanceUpdate(address); err != nil {
		log.Printf("Error sending initial balance update for address %s: %v", address, err)
	}

	// Start the read/write pumps in separate goroutines
	go node.writePump(conn, address)
	go node.readPump(conn, address)
}

func (node *Node) writePump(conn *WebSocketConnection, address string) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		conn.ws.Close()
		node.WebSocketMutex.Lock()
		delete(node.WebSocketConnections, address)
		node.WebSocketMutex.Unlock()
	}()

	for {
		select {
		case message, ok := <-conn.send:
			conn.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				conn.ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := conn.ws.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			conn.ws.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
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

	var balance int64
	var err error
	for attempts := 0; attempts < 3; attempts++ {
		balance, err = node.GetBalance(address)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
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

	select {
	case conn.send <- messageBytes:
		log.Printf("Balance update sent for %s: %d nanoTHRYLOS (%.7f THRYLOS)",
			address, balance, balanceThrylos)
	default:
		if err := conn.ws.WriteJSON(message); err != nil {
			return fmt.Errorf("failed to send balance update: %v", err)
		}
	}

	return nil
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
