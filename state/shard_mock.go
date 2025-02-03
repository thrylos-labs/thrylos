package state

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/thrylos-labs/thrylos/shared"
)

// ShardMetricData struct to hold metrics
type ShardMetricData struct {
	Accesses int64
	Modifies int64
}

// MockNetworkInterface implements the NetworkInterface for testing
type MockNetworkInterface struct {
	messages     [][]byte
	subscribers  []func([]byte) error
	latency      time.Duration
	failureRate  float64
	messageDelay map[string]time.Duration
	peers        map[string]bool // Track connected peers
	mu           sync.RWMutex
}

// NewMockNetworkInterface creates a new mock network interface with configurable parameters
func NewMockNetworkInterface(latency time.Duration, failureRate float64) *MockNetworkInterface {
	return &MockNetworkInterface{
		messages:     make([][]byte, 0),
		subscribers:  make([]func([]byte) error, 0),
		latency:      latency,
		failureRate:  failureRate,
		messageDelay: make(map[string]time.Duration),
		peers:        make(map[string]bool),
	}
}

// BroadcastMessage simulates broadcasting a message across the network
func (m *MockNetworkInterface) BroadcastMessage(message []byte) error {
	m.mu.Lock()
	m.messages = append(m.messages, message)
	subscribers := make([]func([]byte) error, len(m.subscribers))
	copy(subscribers, m.subscribers)
	m.mu.Unlock()

	// Simulate network latency
	if m.latency > 0 {
		time.Sleep(m.latency)
	}

	// Process message type-specific delays
	var networkMsg shared.NetworkMessage
	if err := json.Unmarshal(message, &networkMsg); err == nil {
		if delay, exists := m.messageDelay[networkMsg.Type]; exists {
			time.Sleep(delay)
		}
	}

	// Notify subscribers with simulated network conditions
	for _, subscriber := range subscribers {
		go func(sub func([]byte) error) {
			// Simulate network latency for each subscriber
			time.Sleep(m.latency)
			_ = sub(message)
		}(subscriber)
	}

	return nil
}

// Subscribe adds a new message subscriber
func (m *MockNetworkInterface) Subscribe(handler func([]byte) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribers = append(m.subscribers, handler)
}

// GetMessages returns all broadcasted messages
func (m *MockNetworkInterface) GetMessages() [][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	messages := make([][]byte, len(m.messages))
	copy(messages, m.messages)
	return messages
}

// ClearMessages removes all stored messages
func (m *MockNetworkInterface) ClearMessages() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = make([][]byte, 0)
}

// SetLatency updates the network latency simulation
func (m *MockNetworkInterface) SetLatency(latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latency = latency
}

// SetMessageTypeDelay sets specific delay for different message types
func (m *MockNetworkInterface) SetMessageTypeDelay(msgType string, delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messageDelay[msgType] = delay
}

// SetFailureRate sets the simulated network failure rate
func (m *MockNetworkInterface) SetFailureRate(rate float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failureRate = rate
}

// MockNetworkTest structure for testing
type MockNetworkTest struct {
	network *MockNetworkInterface
	mu      sync.RWMutex
}

func NewMockNetworkTest() *MockNetworkTest {
	return &MockNetworkTest{
		network: NewMockNetworkInterface(100*time.Millisecond, 0.1),
	}
}

// Helper methods for the test implementation
func (m *MockNetworkTest) SimulateStateSync(message []byte) error {
	return m.network.BroadcastMessage(message)
}

func (m *MockNetworkTest) SimulateNetworkPartition(duration time.Duration) {
	m.network.SetFailureRate(1.0)
	time.Sleep(duration)
	m.network.SetFailureRate(0.1)
}

func (m *MockNetworkTest) SimulateNetworkCongestion(latency time.Duration, duration time.Duration) {
	originalLatency := m.network.latency
	m.network.SetLatency(latency)
	time.Sleep(duration)
	m.network.SetLatency(originalLatency)
}

// AddPeer implements the NetworkInterface by adding a new peer to the network
func (m *MockNetworkInterface) AddPeer(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Simulate network conditions
	if m.failureRate > 0 && rand.Float64() < m.failureRate {
		return // Silently fail in case of network issues
	}

	// Add the peer if it doesn't exist
	if _, exists := m.peers[peerID]; !exists {
		m.peers[peerID] = true
	}
}

// GetPeerAddresses returns the list of connected peer addresses
func (m *MockNetworkInterface) GetPeerAddresses() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := make([]string, 0, len(m.peers))
	for peer := range m.peers {
		peers = append(peers, peer)
	}
	return peers
}

// IsConnected checks if a peer is currently connected
func (m *MockNetworkInterface) IsConnected(peerID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	connected, exists := m.peers[peerID]
	return exists && connected
}

// SendMessage sends a message to a specific peer
func (m *MockNetworkInterface) SendMessage(peerID string, message []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if peer exists and is connected
	if connected := m.peers[peerID]; !connected {
		return fmt.Errorf("peer %s not connected", peerID)
	}

	// Simulate network failure based on failure rate
	if m.failureRate > 0 && rand.Float64() < m.failureRate {
		return fmt.Errorf("failed to send message to peer %s due to network conditions", peerID)
	}

	// Simulate network latency
	if m.latency > 0 {
		time.Sleep(m.latency)
	}

	// Process message type-specific delays
	var networkMsg shared.NetworkMessage
	if err := json.Unmarshal(message, &networkMsg); err == nil {
		if delay, exists := m.messageDelay[networkMsg.Type]; exists {
			time.Sleep(delay)
		}
	}

	// Store the message
	m.messages = append(m.messages, message)

	// Notify subscribers
	for _, subscriber := range m.subscribers {
		go func(sub func([]byte) error) {
			_ = sub(message)
		}(subscriber)
	}

	return nil
}

// RemovePeer removes a peer from the network
func (m *MockNetworkInterface) RemovePeer(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.peers, peerID)
}

// Example test function showing usage of the mock network
func ExampleMockNetworkUsage() {
	mockNet := NewMockNetworkInterface(100*time.Millisecond, 0.1)

	// Set up message handling
	mockNet.Subscribe(func(msg []byte) error {
		fmt.Printf("Received message: %s\n", string(msg))
		return nil
	})

	// Broadcast a test message
	testMessage := []byte("test message")
	_ = mockNet.BroadcastMessage(testMessage)

	// Simulate network conditions
	mockNet.SetLatency(200 * time.Millisecond)
	mockNet.SetMessageTypeDelay("STATE_SYNC", 300*time.Millisecond)
}
