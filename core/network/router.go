package network

//Let us put here all codes related to all routes
// network/router.go
package network

import (
    "github.com/gorilla/mux"
    "github.com/thrylos-labs/thrylos/core/node"
)

type Router struct {
    node *node.Node
    rpc  *Handler            // JSON-RPC handler
    ws   *WebSocketManager  // WebSocket handler
}

func NewRouter(node *node.Node) *Router {
    return &Router{
        node: node,
        rpc:  NewHandler(node),
        ws:   NewWebSocketManager(node),
    }
}