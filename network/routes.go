package network

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/types"
)

// // Helper function to check if request is WebSocket
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// SetupRoutes configures the HTTP routes
func (router *Router) SetupRoutes(peerManager *PeerManager) *mux.Router {
	// Store the peer manager reference
	router.peerManager = peerManager

	r := mux.NewRouter()

	// Apply middleware for CORS, logging, etc.
	r.Use(router.middlewareHandler())

	// JSON-RPC endpoint - use ServeHTTP instead of HandleRPC
	r.HandleFunc("/", router.rpc.ServeHTTP).Methods("POST", "OPTIONS")
	r.HandleFunc("/rpc", router.rpc.ServeHTTP).Methods("POST", "OPTIONS")

	// Separate WebSocket endpoint - use WebSocketBalanceHandler
	r.HandleFunc("/ws/balance", router.ws.WebSocketBalanceHandler).Methods("GET", "OPTIONS")

	// P2P protocol routes
	if router.peerManager != nil {
		r.HandleFunc("/peers", router.handleGetPeers).Methods("GET")
		r.HandleFunc("/peers", router.handleAddPeer).Methods("POST")
		r.HandleFunc("/block", router.handleReceiveBlock).Methods("POST")
		// r.HandleFunc("/block/{height:[0-9]+}", router.handleGetBlock).Methods("GET")
		r.HandleFunc("/transaction", router.handleReceiveTransaction).Methods("POST")
		// r.HandleFunc("/blockchain", router.handleGetBlockchainInfo).Methods("GET")
		r.HandleFunc("/ping", router.handlePing).Methods("GET")
	}

	// Additional status endpoint using message bus
	r.HandleFunc("/status", router.handleStatusRequest).Methods("GET")

	// Network information endpoint
	r.HandleFunc("/network", router.handleNetworkInfo).Methods("GET")

	return r
}

// Add the handler methods for P2P endpoints
func (router *Router) handleGetPeers(w http.ResponseWriter, r *http.Request) {
	if router.peerManager == nil {
		http.Error(w, "Peer manager not initialized", http.StatusInternalServerError)
		return
	}

	peers := router.peerManager.GetPeerAddresses()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

func (router *Router) handleAddPeer(w http.ResponseWriter, r *http.Request) {
	if router.peerManager == nil {
		http.Error(w, "Peer manager not initialized", http.StatusInternalServerError)
		return
	}

	var peerInfo struct {
		Address string `json:"address"`
	}

	err := json.NewDecoder(r.Body).Decode(&peerInfo)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if peerInfo.Address == "" {
		http.Error(w, "Peer address is required", http.StatusBadRequest)
		return
	}

	err = router.peerManager.AddPeer(peerInfo.Address, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "peer added"})
}

func (router *Router) handleReceiveBlock(w http.ResponseWriter, r *http.Request) {
	var block types.Block
	err := json.NewDecoder(r.Body).Decode(&block)
	if err != nil {
		http.Error(w, "Invalid block data", http.StatusBadRequest)
		return
	}

	// Process the block through the message bus
	responseCh := make(chan types.Response)
	router.messageBus.Publish(types.Message{
		Type:       types.ProcessBlock,
		Data:       &block,
		ResponseCh: responseCh,
	})

	response := <-responseCh
	if response.Error != nil {
		http.Error(w, response.Error.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "block accepted"})
}

func (router *Router) handleReceiveTransaction(w http.ResponseWriter, r *http.Request) {
	var tx thrylos.Transaction
	err := json.NewDecoder(r.Body).Decode(&tx)
	if err != nil {
		http.Error(w, "Invalid transaction data", http.StatusBadRequest)
		return
	}

	// Process transaction through the message bus
	responseCh := make(chan types.Response)
	router.messageBus.Publish(types.Message{
		Type:       types.ProcessTransaction,
		Data:       &tx,
		ResponseCh: responseCh,
	})

	response := <-responseCh
	if response.Error != nil {
		http.Error(w, response.Error.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "transaction accepted", "txId": tx.Id})
}

func (router *Router) handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (router *Router) handleStatusRequest(w http.ResponseWriter, req *http.Request) {
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

	// Add network information if peer manager is available
	if router.peerManager != nil {
		inbound, outbound := router.peerManager.GetPeerCount()
		info := response.Data.(map[string]interface{})
		info["inboundPeers"] = inbound
		info["outboundPeers"] = outbound
		info["totalPeers"] = inbound + outbound
		info["isSyncing"] = false // You can add a method to check sync status
		response.Data = info
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response.Data)
}

func (router *Router) handleNetworkInfo(w http.ResponseWriter, r *http.Request) {
	if router.peerManager == nil {
		http.Error(w, "Peer manager not initialized", http.StatusInternalServerError)
		return
	}

	inbound, outbound := router.peerManager.GetPeerCount()

	// Get details about peers
	peerAddresses := router.peerManager.GetPeerAddresses()

	networkInfo := map[string]interface{}{
		"inboundPeers":  inbound,
		"outboundPeers": outbound,
		"totalPeers":    inbound + outbound,
		"peers":         peerAddresses,
		"seedPeers":     router.peerManager.SeedPeers,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(networkInfo)
}

// Update the middleware to better handle WebSocket requests
// Update the middleware to better handle WebSocket requests and fix CORS issues
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

			// For JSON-RPC endpoint - set permissive CORS headers for development
			// For JSON-RPC endpoint - set permissive CORS headers for development
			if r.URL.Path == "/" || r.URL.Path == "/rpc" {
				// During development, allow all origins
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

				if r.Method == "OPTIONS" {
					w.WriteHeader(http.StatusNoContent)
					return
				}

				next.ServeHTTP(w, r)
				return
			}

			// Regular request handling with CORS
			allowedOrigins := []string{
				"http://localhost:3000",
				"https://node.thrylos.org",
				"http://localhost:",
				"https://www.thrylos.org",
				// Add your extension's origin if needed
				"chrome-extension://",
			}
			origin := r.Header.Get("Origin")

			// Origin validation
			originAllowed := false
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin ||
					(allowedOrigin == "http://localhost:" && strings.HasPrefix(origin, "http://localhost:")) ||
					(allowedOrigin == "chrome-extension://" && strings.HasPrefix(origin, "chrome-extension://")) {
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
