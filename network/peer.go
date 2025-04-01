package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/types"
)

// PeerConnection manages connection to a peer in the network
type PeerConnection struct {
	messageBus types.MessageBusInterface
	Address    string
	IsInbound  bool
	LastSeen   time.Time
	mu         sync.RWMutex // mutex for this peer connection
}

// Peer management state
type PeerManager struct {
	messageBus            types.MessageBusInterface
	Peers                 map[string]*PeerConnection
	PeerMu                sync.RWMutex
	MaxInbound            int
	MaxOutbound           int
	SeedPeers             []string
	PeerDiscoveryInterval time.Duration
}

// NewPeerManager creates a new peer manager with the message bus
func NewPeerManager(messageBus types.MessageBusInterface, maxInbound, maxOutbound int) *PeerManager {
	return &PeerManager{
		messageBus:            messageBus,
		Peers:                 make(map[string]*PeerConnection),
		MaxInbound:            maxInbound,
		MaxOutbound:           maxOutbound,
		SeedPeers:             []string{},
		PeerDiscoveryInterval: 10 * time.Minute,
	}
}

// NewPeerConnection creates a new peer connection
func NewPeerConnection(messageBus types.MessageBusInterface, address string, isInbound bool) *PeerConnection {
	return &PeerConnection{
		messageBus: messageBus,
		Address:    address,
		IsInbound:  isInbound,
		LastSeen:   time.Now(),
	}
}

// AddPeer adds a new peer to the network
func (pm *PeerManager) AddPeer(address string, isInbound bool) error {
	pm.PeerMu.Lock()
	defer pm.PeerMu.Unlock()

	// Normalize the address
	if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
		address = "http://" + address
	}

	// Check if peer already exists
	if _, exists := pm.Peers[address]; exists {
		log.Printf("Peer %s already in peer list", address)
		return nil
	}

	// Count existing connections
	inboundCount := 0
	outboundCount := 0
	for _, peer := range pm.Peers {
		if peer.IsInbound {
			inboundCount++
		} else {
			outboundCount++
		}
	}

	// Check connection limits
	if isInbound && inboundCount >= pm.MaxInbound {
		return fmt.Errorf("max inbound connections (%d) reached", pm.MaxInbound)
	}
	if !isInbound && outboundCount >= pm.MaxOutbound {
		return fmt.Errorf("max outbound connections (%d) reached", pm.MaxOutbound)
	}

	// Create and add the new peer
	pm.Peers[address] = NewPeerConnection(pm.messageBus, address, isInbound)

	// Notify peers update via message bus
	pm.notifyPeersUpdated()

	peerType := "outbound"
	if isInbound {
		peerType = "inbound"
	}
	log.Printf("Added %s peer: %s", peerType, address)
	return nil
}

// RemovePeer removes a peer from the network
func (pm *PeerManager) RemovePeer(address string) {
	pm.PeerMu.Lock()
	defer pm.PeerMu.Unlock()

	if _, exists := pm.Peers[address]; exists {
		delete(pm.Peers, address)

		// Notify peers update via message bus
		pm.notifyPeersUpdated()

		log.Printf("Removed peer: %s", address)
	}
}

// GetPeerCount returns the count of inbound and outbound peers
func (pm *PeerManager) GetPeerCount() (inbound, outbound int) {
	pm.PeerMu.RLock()
	defer pm.PeerMu.RUnlock()

	for _, peer := range pm.Peers {
		if peer.IsInbound {
			inbound++
		} else {
			outbound++
		}
	}
	return
}

// GetPeerAddresses returns a list of all peer addresses
func (pm *PeerManager) GetPeerAddresses() []string {
	pm.PeerMu.RLock()
	defer pm.PeerMu.RUnlock()

	addresses := make([]string, 0, len(pm.Peers))
	for _, peer := range pm.Peers {
		addresses = append(addresses, peer.Address)
	}
	return addresses
}

// notifyPeersUpdated notifies the system about peer list changes
func (pm *PeerManager) notifyPeersUpdated() {
	peerAddresses := pm.GetPeerAddresses()

	// Send message via message bus about peer list update
	responseCh := make(chan types.Response)
	pm.messageBus.Publish(types.Message{
		Type:       types.UpdatePeerList,
		Data:       peerAddresses,
		ResponseCh: responseCh,
	})

	// No need to wait for response
}

// DiscoverPeers attempts to discover new peers from the current peer list
func (pm *PeerManager) DiscoverPeers() {
	log.Println("Starting peer discovery...")
	maxRetries := 5
	retryInterval := time.Second * 5

	pm.PeerMu.RLock()
	currentPeers := make([]*PeerConnection, 0, len(pm.Peers))
	for _, peer := range pm.Peers {
		currentPeers = append(currentPeers, peer)
	}
	pm.PeerMu.RUnlock()

	// If we have no peers, try seed peers
	if len(currentPeers) == 0 && len(pm.SeedPeers) > 0 {
		log.Println("No peers available, trying seed peers...")
		for _, seedPeer := range pm.SeedPeers {
			pm.AddPeer(seedPeer, false)
		}

		// Refresh the peer list
		pm.PeerMu.RLock()
		currentPeers = make([]*PeerConnection, 0, len(pm.Peers))
		for _, peer := range pm.Peers {
			currentPeers = append(currentPeers, peer)
		}
		pm.PeerMu.RUnlock()
	}

	// Still no peers after trying seeds
	if len(currentPeers) == 0 {
		log.Println("No peers available for discovery, even after trying seeds.")
		return
	}

	for i := 0; i < maxRetries; i++ {
		allPeersDiscovered := true

		for _, peer := range currentPeers {
			log.Printf("Requesting peers from: %s", peer.Address)
			resp, err := http.Get(peer.Address + "/peers")
			if err != nil {
				log.Printf("Failed to discover peers from %s: %v", peer.Address, err)
				allPeersDiscovered = false
				continue
			}

			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()

			if err != nil {
				log.Printf("Failed to read response from %s: %v", peer.Address, err)
				allPeersDiscovered = false
				continue
			}

			var discoveredPeers []string
			if err := json.Unmarshal(body, &discoveredPeers); err != nil {
				log.Printf("Failed to decode peers from %s: %v", peer.Address, err)
				allPeersDiscovered = false
				continue
			}

			for _, discoveredPeer := range discoveredPeers {
				if err := pm.AddPeer(discoveredPeer, false); err != nil {
					log.Printf("Failed to add discovered peer %s: %v", discoveredPeer, err)
				}
			}

			// Update last seen time
			peer.mu.Lock()
			peer.LastSeen = time.Now()
			peer.mu.Unlock()
		}

		if allPeersDiscovered {
			log.Println("Successfully discovered peers.")
			return
		}

		log.Printf("Retrying peer discovery in %v... (%d/%d)", retryInterval, i+1, maxRetries)
		time.Sleep(retryInterval)
	}

	log.Println("Failed to discover all peers after maximum retries.")
}

// SyncWithPeer synchronizes blockchain state with a specific peer
func (pm *PeerManager) SyncWithPeer(peerAddress string) error {
	log.Printf("Syncing with peer: %s", peerAddress)

	resp, err := http.Get(peerAddress + "/blockchain")
	if err != nil {
		log.Printf("Error fetching the blockchain from %s: %v", peerAddress, err)
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response from %s: %v", peerAddress, err)
		return err
	}

	// Get the current blockchain height
	heightCh := make(chan types.Response)
	pm.messageBus.Publish(types.Message{
		Type:       types.GetBlockchainInfo,
		Data:       "height",
		ResponseCh: heightCh,
	})
	heightResp := <-heightCh

	var currentHeight int32
	if heightResp.Error == nil {
		if height, ok := heightResp.Data.(int32); ok {
			currentHeight = height
		}
	}

	// Parse peer's blockchain data
	var peerBlockchainData map[string]interface{}
	if err := json.Unmarshal(body, &peerBlockchainData); err != nil {
		log.Printf("Error unmarshalling blockchain data: %v", err)
		return err
	}

	// Extract peer's blockchain height
	var peerHeight int32
	if heightFloat, ok := peerBlockchainData["height"].(float64); ok {
		peerHeight = int32(heightFloat)
	}

	// If peer has higher blockchain, sync blocks
	if peerHeight > currentHeight {
		log.Printf("Peer %s has higher blockchain (height: %d > %d), syncing blocks...",
			peerAddress, peerHeight, currentHeight)

		// For each missing block, fetch and process
		for height := currentHeight + 1; height <= peerHeight; height++ {
			// Get block from peer
			blockResp, err := http.Get(fmt.Sprintf("%s/block/%d", peerAddress, height))
			if err != nil {
				log.Printf("Error fetching block %d: %v", height, err)
				continue
			}

			blockBody, err := ioutil.ReadAll(blockResp.Body)
			blockResp.Body.Close()

			if err != nil {
				log.Printf("Error reading block %d response: %v", height, err)
				continue
			}

			var block types.Block
			if err := json.Unmarshal(blockBody, &block); err != nil {
				log.Printf("Error unmarshalling block %d: %v", height, err)
				continue
			}

			// Process block via message bus
			processCh := make(chan types.Response)
			pm.messageBus.Publish(types.Message{
				Type:       types.ProcessBlock,
				Data:       &block,
				ResponseCh: processCh,
			})

			// Wait for processing to complete
			processResp := <-processCh
			if processResp.Error != nil {
				log.Printf("Error processing block %d: %v", height, processResp.Error)
				return processResp.Error
			}
		}

		log.Printf("Successfully synced %d blocks from peer %s", peerHeight-currentHeight, peerAddress)
	} else {
		log.Printf("No new blocks from peer %s (peer height: %d, our height: %d)",
			peerAddress, peerHeight, currentHeight)
	}

	return nil
}

// SyncBlockchain synchronizes with all peers to ensure the latest blockchain state
func (pm *PeerManager) SyncBlockchain() {
	log.Println("Starting blockchain synchronization...")

	pm.PeerMu.RLock()
	peers := make([]*PeerConnection, 0, len(pm.Peers))
	for _, peer := range pm.Peers {
		peers = append(peers, peer)
	}
	pm.PeerMu.RUnlock()

	if len(peers) == 0 {
		log.Println("No peers available for blockchain synchronization.")
		return
	}

	for _, peer := range peers {
		if err := pm.SyncWithPeer(peer.Address); err != nil {
			log.Printf("Failed to sync with peer %s: %v", peer.Address, err)
		}
	}

	log.Println("Blockchain synchronization completed.")
}

// BroadcastBlock sends a block to all peers
func (pm *PeerManager) BroadcastBlock(block *types.Block) {
	blockData, err := json.Marshal(block)
	if err != nil {
		log.Printf("Failed to serialize block: %v", err)
		return
	}

	pm.PeerMu.RLock()
	peers := make([]*PeerConnection, 0, len(pm.Peers))
	for _, peer := range pm.Peers {
		peers = append(peers, peer)
	}
	pm.PeerMu.RUnlock()

	log.Printf("Broadcasting block %s to %d peers", block.Hash, len(peers))

	var wg sync.WaitGroup
	for _, peer := range peers {
		wg.Add(1)
		go func(p *PeerConnection) {
			defer wg.Done()

			resp, err := http.Post(p.Address+"/block", "application/json", bytes.NewBuffer(blockData))
			if err != nil {
				log.Printf("Failed to post block to peer %s: %v", p.Address, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
				log.Printf("Received non-OK response when broadcasting block to peer %s: %s",
					p.Address, resp.Status)
			}

			// Update last seen time
			p.mu.Lock()
			p.LastSeen = time.Now()
			p.mu.Unlock()
		}(peer)
	}

	// Wait for all broadcast operations to complete
	wg.Wait()
	log.Printf("Block broadcast completed")
}

// BroadcastTransaction sends a transaction to all peers
func (pm *PeerManager) BroadcastTransaction(tx *thrylos.Transaction) error {
	txData, err := json.Marshal(tx)
	if err != nil {
		log.Printf("Failed to serialize transaction: %v", err)
		return err
	}

	pm.PeerMu.RLock()
	peers := make([]*PeerConnection, 0, len(pm.Peers))
	for _, peer := range pm.Peers {
		peers = append(peers, peer)
	}
	pm.PeerMu.RUnlock()

	log.Printf("Broadcasting transaction %s to %d peers", tx.Id, len(peers))

	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		broadcastErr error
	)

	for _, peer := range peers {
		wg.Add(1)
		go func(p *PeerConnection) {
			defer wg.Done()

			url := fmt.Sprintf("%s/transaction", p.Address)
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(txData))
			if err != nil {
				log.Printf("Failed to post transaction to peer %s: %v", p.Address, err)
				mu.Lock()
				broadcastErr = err
				mu.Unlock()
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
				log.Printf("Received non-OK response when broadcasting transaction to peer %s: %s",
					p.Address, resp.Status)
				mu.Lock()
				broadcastErr = fmt.Errorf("failed to broadcast to peer %s, received status %s",
					p.Address, resp.Status)
				mu.Unlock()
			}

			// Update last seen time
			p.mu.Lock()
			p.LastSeen = time.Now()
			p.mu.Unlock()
		}(peer)
	}

	// Wait for all broadcast operations to complete
	wg.Wait()

	if broadcastErr != nil {
		log.Printf("Transaction broadcast completed with errors")
		return broadcastErr
	}

	log.Printf("Transaction broadcast completed successfully")
	return nil
}

// PingPeers checks the health of all connected peers
func (pm *PeerManager) PingPeers() {
	log.Println("Pinging all peers...")

	pm.PeerMu.RLock()
	peers := make([]*PeerConnection, 0, len(pm.Peers))
	for _, peer := range pm.Peers {
		peers = append(peers, peer)
	}
	pm.PeerMu.RUnlock()

	var wg sync.WaitGroup
	for _, peer := range peers {
		wg.Add(1)
		go func(p *PeerConnection) {
			defer wg.Done()

			resp, err := http.Get(p.Address + "/ping")
			if err != nil {
				log.Printf("Failed to ping peer %s: %v", p.Address, err)
				// Consider removing unresponsive peers
				if strings.Contains(err.Error(), "connection refused") ||
					strings.Contains(err.Error(), "no route to host") ||
					strings.Contains(err.Error(), "i/o timeout") {
					log.Printf("Removing unresponsive peer %s", p.Address)
					pm.RemovePeer(p.Address)
				}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Printf("Unhealthy peer %s with status: %d", p.Address, resp.StatusCode)
			} else {
				// Update last seen time for responsive peers
				p.mu.Lock()
				p.LastSeen = time.Now()
				p.mu.Unlock()
			}
		}(peer)
	}

	wg.Wait()
	log.Printf("Ping completed for %d peers", len(peers))
}

// SendVote sends a vote to a specific peer
func (pc *PeerConnection) SendVote(vote types.Vote) error {
	voteData, err := json.Marshal(vote)
	if err != nil {
		return fmt.Errorf("failed to serialize vote: %v", err)
	}

	url := fmt.Sprintf("%s/vote", pc.Address)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(voteData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK response: %s", resp.Status)
	}

	// Update last seen time
	pc.mu.Lock()
	pc.LastSeen = time.Now()
	pc.mu.Unlock()

	return nil
}

// BroadcastVote sends a vote to all peers
func (pm *PeerManager) BroadcastVote(vote types.Vote) error {
	voteData, err := json.Marshal(vote)
	if err != nil {
		log.Printf("Failed to serialize vote: %v", err)
		return err
	}

	pm.PeerMu.RLock()
	peers := make([]*PeerConnection, 0, len(pm.Peers))
	for _, peer := range pm.Peers {
		peers = append(peers, peer)
	}
	pm.PeerMu.RUnlock()

	log.Printf("Broadcasting vote for block %s to %d peers", vote.BlockHash, len(peers))

	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		broadcastErr error
	)

	for _, peer := range peers {
		wg.Add(1)
		go func(p *PeerConnection) {
			defer wg.Done()

			url := fmt.Sprintf("%s/vote", p.Address)
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(voteData))
			if err != nil {
				log.Printf("Failed to post vote to peer %s: %v", p.Address, err)
				mu.Lock()
				broadcastErr = err
				mu.Unlock()
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Printf("Received non-OK response when broadcasting vote to peer %s: %s",
					p.Address, resp.Status)
				mu.Lock()
				broadcastErr = fmt.Errorf("failed to broadcast vote to peer %s, received status %s",
					p.Address, resp.Status)
				mu.Unlock()
			}

			// Update last seen time
			p.mu.Lock()
			p.LastSeen = time.Now()
			p.mu.Unlock()
		}(peer)
	}

	// Wait for all broadcast operations to complete
	wg.Wait()

	if broadcastErr != nil {
		log.Printf("Vote broadcast completed with errors")
		return broadcastErr
	}

	log.Printf("Vote broadcast completed successfully")
	return nil
}

// StartPeerManagement initiates periodic peer discovery and health checks
func (pm *PeerManager) StartPeerManagement() {
	// Run initial peer discovery
	pm.DiscoverPeers()

	// Set up ticker for periodic peer discovery
	discoveryTicker := time.NewTicker(pm.PeerDiscoveryInterval)
	pingTicker := time.NewTicker(2 * time.Minute)

	go func() {
		for {
			select {
			case <-discoveryTicker.C:
				pm.DiscoverPeers()
			case <-pingTicker.C:
				pm.PingPeers()
			}
		}
	}()

	log.Println("Peer management started")
}
