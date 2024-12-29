package core

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Helper function to check if request is WebSocket
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// Middleware handler function
func (node *Node) middlewareHandler() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Request logging
			log.Printf("[%s] Request: %s %s from %s",
				time.Now().Format(time.RFC3339),
				r.Method,
				r.URL.Path,
				r.RemoteAddr,
			)

			// CORS configuration
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

			// Security headers
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Handle preflight
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Origin validation for non-WebSocket requests
			if !originAllowed && !isWebSocketRequest(r) {
				if r.Method != "OPTIONS" {
					log.Printf("Blocked request from unauthorized origin: %s", origin)
					http.Error(w, "Unauthorized origin", http.StatusForbidden)
					return
				}
			}

			// Set content type
			if !isWebSocketRequest(r) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
			}

			// Request tracking
			ctx := context.WithValue(r.Context(), "request_start_time", time.Now())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (node *Node) SetupRoutes() *mux.Router {
	r := mux.NewRouter()

	// Apply middleware for CORS, logging, etc.
	r.Use(node.middlewareHandler())

	// Main WebSocket + JSON-RPC endpoint
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Handle both WebSocket and HTTP requests
		if isWebSocketRequest(r) {
			node.handleWebSocketConnection(w, r)
			return
		}
		// Handle regular JSON-RPC requests
		node.JSONRPCHandler(w, r)
	})

	return r
}

func (node *Node) handleWebSocketConnection(w http.ResponseWriter, r *http.Request) {
	// Get address from query params
	address := r.URL.Query().Get("address")
	if address == "" {
		log.Println("Blockchain address is required")
		http.Error(w, "Blockchain address is required", http.StatusBadRequest)
		return
	}

	// Upgrade to WebSocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// Create new connection
	conn := NewWebSocketConnection(ws)

	// Store connection in node's connections map
	node.WebSocketMutex.Lock()
	node.WebSocketConnections[address] = conn
	node.WebSocketMutex.Unlock()

	// Start message handlers
	go node.readPump(conn, address)
	go node.writePump(conn, address)
}
