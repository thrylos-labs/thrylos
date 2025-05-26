package network

import (
	"log"

	"github.com/thrylos-labs/thrylos/config"
	"github.com/thrylos-labs/thrylos/types"
)

type Router struct {
	rpc        *Handler          // JSON-RPC handler
	ws         *WebSocketManager // WebSocket handler
	messageBus types.MessageBusInterface
	// REMOVED: peerManager *PeerManager // Old Peer manager reference
	Libp2pManager *Libp2pManager // NEW: Reference to the Libp2p network manager
}

// NewRouter creates a new Router with the message bus, configuration, and Libp2pManager.
func NewRouter(messageBus types.MessageBusInterface, cfg *config.Config, lm *Libp2pManager) *Router { // <-- ADD lm *Libp2pManager argument
	if cfg == nil {
		log.Panic("FATAL: NewRouter called with nil config")
	}
	if lm == nil { // It's important to pass a non-nil Libp2pManager
		log.Panic("FATAL: NewRouter called with nil Libp2pManager")
	}

	router := &Router{
		messageBus:    messageBus,
		Libp2pManager: lm, // Store the Libp2pManager
	}

	router.rpc = NewHandler(messageBus, cfg)
	router.ws = NewWebSocketManager(messageBus)

	return router
}
