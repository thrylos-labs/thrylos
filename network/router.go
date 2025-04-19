package network

import (
	"log"

	"github.com/thrylos-labs/thrylos/config"
	"github.com/thrylos-labs/thrylos/types"
)

type Router struct {
	rpc         *Handler          // JSON-RPC handler
	ws          *WebSocketManager // WebSocket handler
	messageBus  types.MessageBusInterface
	peerManager *PeerManager // Peer manager reference
}

func NewRouter(messageBus types.MessageBusInterface, cfg *config.Config) *Router { // <-- ADD cfg argument
	// Add a check for nil config for robustness
	if cfg == nil {
		log.Panic("FATAL: NewRouter called with nil config")
	}

	router := &Router{
		messageBus: messageBus,
	}

	// --- MODIFIED Handler Initialization ---
	// Pass both messageBus and cfg to NewHandler
	router.rpc = NewHandler(messageBus, cfg) // <-- PASS cfg
	// Assuming NewWebSocketManager doesn't need config, otherwise update it too
	router.ws = NewWebSocketManager(messageBus)

	return router
}
