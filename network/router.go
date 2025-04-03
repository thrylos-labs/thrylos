package network

import (
	"github.com/thrylos-labs/thrylos/types"
)

type Router struct {
	rpc        *Handler          // JSON-RPC handler
	ws         *WebSocketManager // WebSocket handler
	messageBus types.MessageBusInterface
}

func NewRouter(messageBus types.MessageBusInterface) *Router {
	router := &Router{
		messageBus: messageBus,
	}

	// Initialize handlers with the message bus only
	router.rpc = NewHandler(messageBus)
	router.ws = NewWebSocketManager(messageBus)

	return router
}
