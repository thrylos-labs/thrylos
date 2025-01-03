package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	thrylos "github.com/thrylos-labs/thrylos"
)

// Peer Management: Nodes add new peers to their network, avoiding duplicates, and adjust protocols (HTTP/HTTPS) as necessary.
// Peer Discovery: Nodes discover new peers by requesting peer lists from known peers and integrating the discovered peers into their own peer list.
// Blockchain Synchronization: Nodes synchronize their blockchain with peers to maintain a consistent state across the network.

type PeerConnection struct {
	Address   string
	IsInbound bool
	LastSeen  time.Time
}

func (node *Node) AddPeer(address string, isInbound bool) error {
	node.PeerMu.Lock()
	defer node.PeerMu.Unlock()

	inboundCount := 0
	outboundCount := 0
	for _, peer := range node.Peers {
		if peer.IsInbound {
			inboundCount++
		} else {
			outboundCount++
		}
	}

	if isInbound && inboundCount >= node.MaxInbound {
		return fmt.Errorf("max inbound connections (%d) reached", node.MaxInbound)
	}
	if !isInbound && outboundCount >= node.MaxOutbound {
		return fmt.Errorf("max outbound connections (%d) reached", node.MaxOutbound)
	}

	if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
		address = "http://" + address
	}

	node.Peers[address] = &PeerConnection{
		Address:   address,
		IsInbound: isInbound,
		LastSeen:  time.Now(),
	}
	return nil
}

func (node *Node) RemovePeer(address string) {
	node.PeerMu.Lock()
	defer node.PeerMu.Unlock()
	delete(node.Peers, address)
}

func (node *Node) GetPeerCount() (inbound, outbound int) {
	node.PeerMu.RLock()
	defer node.PeerMu.RUnlock()

	for _, peer := range node.Peers {
		if peer.IsInbound {
			inbound++
		} else {
			outbound++
		}
	}
	return
}

func (node *Node) GetPeerAddresses() []string {
	node.PeerMu.RLock()
	defer node.PeerMu.RUnlock()

	addresses := make([]string, 0, len(node.Peers))
	for _, peer := range node.Peers {
		addresses = append(addresses, peer.Address)
	}
	return addresses
}

// DiscoverPeers attempts to discover new peers from the current peer list
func (node *Node) DiscoverPeers() {
	maxRetries := 5
	retryInterval := time.Second * 5

	for i := 0; i < maxRetries; i++ {
		allPeersDiscovered := true

		for _, peer := range node.Peers {
			resp, err := http.Get(peer.Address + "/peers")
			if err != nil {
				fmt.Println("Failed to discover peers:", err)
				allPeersDiscovered = false
				break
			}
			defer resp.Body.Close()

			var discoveredPeers []string
			if err := json.NewDecoder(resp.Body).Decode(&discoveredPeers); err != nil {
				fmt.Printf("Failed to decode peers from %s: %v\n", peer.Address, err)
				allPeersDiscovered = false
				break
			}

			for _, discoveredPeer := range discoveredPeers {
				node.AddPeer(discoveredPeer, false) // false = outbound connection
			}
		}

		if allPeersDiscovered {
			fmt.Println("Successfully discovered all peers.")
			return
		}

		fmt.Printf("Retrying peer discovery in %v... (%d/%d)\n", retryInterval, i+1, maxRetries)
		time.Sleep(retryInterval)
	}

	fmt.Println("Failed to discover all peers after maximum retries.")
}

// SyncWithPeer synchronizes blockchain state with a specific peer
func (node *Node) SyncWithPeer(peer string) {
	resp, err := http.Get(peer + "/blockchain")
	if err != nil {
		fmt.Println("Error fetching the blockchain:", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	peerBlockchain := &Blockchain{}
	err = json.Unmarshal(body, peerBlockchain)
	if err != nil {
		fmt.Println("Error unmarshalling the blockchain:", err)
		return
	}

	if len(peerBlockchain.Blocks) > len(node.Blockchain.Blocks) {
		node.Blockchain.Mu.Lock()
		node.Blockchain.Blocks = peerBlockchain.Blocks
		node.Blockchain.Mu.Unlock()
	}
}

// SyncBlockchain synchronizes with all peers to ensure the latest blockchain state
func (node *Node) SyncBlockchain() {
	for _, peer := range node.Peers {
		resp, err := http.Get(peer.Address + "/blockchain")
		if err != nil {
			fmt.Println("Failed to get blockchain from peer:", err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Println("Non-OK HTTP status from peer:", resp.StatusCode)
			resp.Body.Close()
			continue
		}

		var peerBlockchain Blockchain
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&peerBlockchain)
		resp.Body.Close()

		if err != nil {
			fmt.Println("Failed to deserialize blockchain:", err)
			continue
		}

		if len(peerBlockchain.Blocks) > len(node.Blockchain.Blocks) {
			for i := len(node.Blockchain.Blocks); i < len(peerBlockchain.Blocks); i++ {
				node.Blockchain.Blocks = append(node.Blockchain.Blocks, peerBlockchain.Blocks[i])
			}
		}
	}
}

// Broadcast sends the current blockchain state to all peers
func (node *Node) Broadcast() {
	data, err := json.Marshal(node.Blockchain)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	for _, peer := range node.Peers {
		resp, err := http.Post(peer.Address+"/blockchain", "application/json", bytes.NewBuffer(data))
		if err != nil {
			fmt.Println("Failed to broadcast to peer:", peer)
			continue
		}
		resp.Body.Close()
	}
}

// BroadcastBlock sends a block to all peers
func (node *Node) BroadcastBlock(block *Block) {
	blockData, err := json.Marshal(block)
	if err != nil {
		fmt.Println("Failed to serialize block:", err)
		return
	}

	for _, peer := range node.Peers {
		resp, err := http.Post(peer.Address+"/block", "application/json", bytes.NewBuffer(blockData))
		if err != nil {
			fmt.Printf("Failed to post block to peer %s: %v\n", peer.Address, err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Received non-OK response when broadcasting block to peer %s: %s\n", peer.Address, resp.Status)
		}
		resp.Body.Close()
	}
}

// BroadcastTransaction sends a transaction to all peers
func (node *Node) BroadcastTransaction(tx *thrylos.Transaction) error {
	txData, err := json.Marshal(tx)
	if err != nil {
		fmt.Println("Failed to serialize transaction:", err)
		return err
	}

	var broadcastErr error
	for _, peer := range node.Peers {
		url := fmt.Sprintf("%s/transaction", peer.Address)
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(txData))
		if err != nil {
			fmt.Println("Failed to post transaction to peer:", err)
			broadcastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			fmt.Printf("Received non-OK response when broadcasting transaction to peer: %s, Status: %s\n", peer.Address, resp.Status)
			broadcastErr = fmt.Errorf("failed to broadcast to peer %s, received status %s", peer.Address, resp.Status)
		}
		resp.Body.Close()
	}
	return broadcastErr
}

// Utility functions for peer management
func (node *Node) GetPeers() []string {
	return node.GetPeerAddresses() // Use existing helper function
}

// PingPeers checks the health of all connected peers
func (node *Node) PingPeers() {
	for _, peer := range node.Peers {
		resp, err := http.Get(peer.Address + "/ping")
		if err != nil {
			log.Printf("Failed to ping peer %s: %v", peer.Address, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("Unhealthy peer %s with status: %d", peer.Address, resp.StatusCode)
		}
	}
}
