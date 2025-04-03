package network

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/thrylos-labs/thrylos/types"
)

// // Helper function to check if request is WebSocket
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

func (router *Router) SetupRoutes() *mux.Router {
	r := mux.NewRouter()

	// Apply middleware for CORS, logging, etc.
	r.Use(router.middlewareHandler())

	// JSON-RPC endpoint - use ServeHTTP instead of HandleRPC
	r.HandleFunc("/", router.rpc.ServeHTTP).Methods("POST", "OPTIONS")

	// Separate WebSocket endpoint - use WebSocketBalanceHandler
	r.HandleFunc("/ws/balance", router.ws.WebSocketBalanceHandler).Methods("GET", "OPTIONS")

	// Additional status endpoint using message bus
	r.HandleFunc("/status", func(w http.ResponseWriter, req *http.Request) {
		responseCh := make(chan types.Response)
		router.messageBus.Publish(types.Message{
			Type:       types.GetBlockchainInfo,
			ResponseCh: responseCh,
		})

		response := <-responseCh
		if response.Error != nil {
			http.Error(w, response.Error.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response.Data)
	}).Methods("GET")

	return r
}

// Update the middleware to better handle WebSocket requests
func (router *Router) middlewareHandler() mux.MiddlewareFunc {
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
