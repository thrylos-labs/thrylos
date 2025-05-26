package network

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/thrylos-labs/thrylos/types"
	// Needed for Peer.ID string conversion
)

// Helper function to check if request is WebSocket
func isWebSocketRequest(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// SetupRoutes configures the HTTP routes.
// It no longer takes a peerManager argument.
func (router *Router) SetupRoutes() *mux.Router {
	r := mux.NewRouter()
	r.Use(router.middlewareHandler())

	// JSON-RPC endpoints (Client-facing - KEEP)
	r.HandleFunc("/", router.rpc.ServeHTTP).Methods("POST", "OPTIONS")
	r.HandleFunc("/rpc", router.rpc.ServeHTTP).Methods("POST", "OPTIONS")

	// Separate WebSocket endpoint (Client-facing - KEEP)
	r.HandleFunc("/ws/balance", router.ws.WebSocketBalanceHandler).Methods("GET", "OPTIONS")

	// Additional status endpoint using message bus (updated to use Libp2pManager for peer info)
	r.HandleFunc("/status", router.handleStatusRequest).Methods("GET")

	// Network information endpoint (updated to use Libp2pManager for peer info)
	r.HandleFunc("/network", router.handleNetworkInfo).Methods("GET")

	return r
}

// handleStatusRequest now retrieves peer count from Libp2pManager
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

	info := response.Data.(map[string]interface{})

	// Add network information from Libp2pManager
	if router.Libp2pManager != nil && router.Libp2pManager.Host != nil {
		connectedPeers := router.Libp2pManager.Host.Network().Peers()
		info["connectedPeersCount"] = len(connectedPeers)
		// You might want to distinguish inbound/outbound if Libp2pManager provides that info
		info["isSyncing"] = false // Placeholder, should come from blockchain core
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response.Data)
}

// handleNetworkInfo now retrieves peer details from Libp2pManager
func (router *Router) handleNetworkInfo(w http.ResponseWriter, r *http.Request) {
	if router.Libp2pManager == nil || router.Libp2pManager.Host == nil {
		http.Error(w, "Libp2p network manager not initialized", http.StatusInternalServerError)
		return
	}

	connectedPeerIDs := router.Libp2pManager.Host.Network().Peers()
	peerIDStrings := make([]string, len(connectedPeerIDs))
	for i, pid := range connectedPeerIDs {
		// FIX: Use .String() instead of .Pretty()
		peerIDStrings[i] = pid.String() // Convert Peer.ID to string
	}

	networkInfo := map[string]interface{}{
		"connectedPeersCount": len(connectedPeerIDs),
		"peers":               peerIDStrings,
		"listenAddresses": func() []string {
			addrs := router.Libp2pManager.Host.Addrs()
			sAddrs := make([]string, len(addrs))
			for i, addr := range addrs {
				sAddrs[i] = addr.String()
			}
			return sAddrs
		}(),
		// FIX: Use .String() instead of .Pretty()
		"localPeerID": router.Libp2pManager.Host.ID().String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(networkInfo)
}

// middlewareHandler remains unchanged.
func (router *Router) middlewareHandler() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[%s] Request: %s %s from %s",
				time.Now().Format(time.RFC3339),
				r.Method,
				r.URL.Path,
				r.RemoteAddr,
			)
			if isWebSocketRequest(r) {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				next.ServeHTTP(w, r)
				return
			}
			if r.URL.Path == "/" || r.URL.Path == "/rpc" {
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
			allowedOrigins := []string{
				"http://localhost:3000",
				"https://node.thrylos.org",
				"http://localhost:",
				"https://www.thrylos.org",
				"chrome-extension://",
			}
			origin := r.Header.Get("Origin")
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
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
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
