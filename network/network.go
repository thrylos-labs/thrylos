package network

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
)

type DefaultNetwork struct {
	peers  map[string]bool
	logger *log.Logger
}

func NewDefaultNetwork() *DefaultNetwork {
	return &DefaultNetwork{
		peers:  make(map[string]bool),
		logger: log.Default(),
	}
}

func (n *DefaultNetwork) SendMessage(nodeAddress string, message []byte) error {
	if !n.peers[nodeAddress] {
		return fmt.Errorf("node not connected: %s", nodeAddress)
	}

	resp, err := http.Post(nodeAddress+"/message", "application/json", bytes.NewBuffer(message))
	if err != nil {
		n.logger.Printf("Failed to send message to %s: %v", nodeAddress, err)
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (n *DefaultNetwork) BroadcastMessage(message []byte) error {
	for peer := range n.peers {
		if err := n.SendMessage(peer, message); err != nil {
			n.logger.Printf("Error broadcasting to peer %s: %v", peer, err)
		}
	}
	return nil
}

func (n *DefaultNetwork) GetPeerAddresses() []string {
	addresses := make([]string, 0, len(n.peers))
	for addr := range n.peers {
		addresses = append(addresses, addr)
	}
	return addresses
}

func (n *DefaultNetwork) IsConnected(nodeAddress string) bool {
	return n.peers[nodeAddress]
}

func (n *DefaultNetwork) AddPeer(address string) {
	n.peers[address] = true
	n.logger.Printf("Added peer: %s", address)
}

func (n *DefaultNetwork) RemovePeer(address string) {
	delete(n.peers, address)
	n.logger.Printf("Removed peer: %s", address)
}
