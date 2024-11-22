package shared

import "time"

// NetworkInterface defines the methods required for network communication
type NetworkInterface interface {
	SendMessage(nodeAddress string, message []byte) error
	BroadcastMessage(message []byte) error
	GetPeerAddresses() []string
	IsConnected(nodeAddress string) bool
	AddPeer(address string)
	RemovePeer(address string)
}

// NetworkMessage represents a message sent between nodes
type NetworkMessage struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}
