package network

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/thrylos-labs/thrylos/node"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type Router struct {
	node *node.Node
	rpc  *Handler          // JSON-RPC handler
	ws   *WebSocketManager // WebSocket handler
}

func NewRouter(node *node.Node) *Router {
	return &Router{
		node: node,
		rpc:  NewHandler(node),
		ws:   NewWebSocketManager(node),
	}
}

// Helper function to check if request is WebSocket
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

func (r *Router) SetupRoutes() *mux.Router {
	router := mux.NewRouter()

	// Apply middleware for CORS, logging, etc.
	router.Use(node.middlewareHandler())

	// JSON-RPC endpoint
	router.HandleFunc("/", node.JSONRPCHandler).Methods("POST", "OPTIONS")

	// Separate WebSocket endpoint
	router.HandleFunc("/ws/balance", func(w http.ResponseWriter, r *http.Request) {
		// Add cors headers specifically for WebSocket
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		address := r.URL.Query().Get("address")
		if address == "" {
			http.Error(w, "Address parameter is required", http.StatusBadRequest)
			return
		}

		// Check if it's a WebSocket request
		if !isWebSocketRequest(r) {
			http.Error(w, "Expected WebSocket connection", http.StatusBadRequest)
			return
		}

		node.handleWebSocketConnection(w, r)
	}).Methods("GET", "OPTIONS")

	return router
}

func (r *Router) handleWebSocketConnection(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")

	// Configure the upgrader with more permissive settings
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			// Add more comprehensive origin checking if needed
			return true
		},
	}

	// Upgrade the connection
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	log.Printf("WebSocket connection established for address: %s", address)

	// Create new connection with explicit configuration
	conn := NewWebSocketConnection(ws)

	// Store connection safely
	node.WebSocketMutex.Lock()
	// Clean up existing connection if it exists
	if existingConn, exists := node.WebSocketConnections[address]; exists {
		existingConn.close()
	}
	node.WebSocketConnections[address] = conn
	node.WebSocketMutex.Unlock()

	// Send initial balance
	if err := node.SendBalanceUpdate(address); err != nil {
		log.Printf("Error sending initial balance: %v", err)
	}

	// Start handlers
	go node.readPump(conn, address)
	go node.writePump(conn, address)
}

// Update the middleware to better handle WebSocket requests
func (r *Router) middlewareHandler() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Log incoming request
			log.Printf("[%s] Request: %s %s from %s",
				time.Now().Format(time.RFC3339),
				r.Method,
				r.URL.Path,
				r.RemoteAddr,
			)

			// Different handling for WebSocket and regular requests
			if isWebSocketRequest(r) {
				// Minimal headers for WebSocket
				w.Header().Set("Access-Control-Allow-Origin", "*")
				next.ServeHTTP(w, r)
				return
			}

			// Regular request handling with CORS
			allowedOrigins := []string{
				"http://localhost:3000",
				"https://node.thrylos.org",
				"http://localhost:",
				"https://www.thrylos.org",
			}
			origin := r.Header.Get("Origin")

			// Origin validation
			originAllowed := false
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin ||
					(allowedOrigin == "http://localhost:" && strings.HasPrefix(origin, "http://localhost:")) {
					originAllowed = true
					w.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}

			// Set comprehensive headers for regular requests
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")

			// Security headers
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			if !originAllowed {
				http.Error(w, "Unauthorized origin", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
