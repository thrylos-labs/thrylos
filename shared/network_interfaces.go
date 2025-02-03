package shared

// NetworkInterface defines the methods required for network communication
type NetworkInterface interface {
	SendMessage(nodeAddress string, message []byte) error
	BroadcastMessage(message []byte) error
	GetPeerAddresses() []string
	IsConnected(nodeAddress string) bool
	AddPeer(address string)
	RemovePeer(address string)
}
