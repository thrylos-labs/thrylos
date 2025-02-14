package types

import (
	"time"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 512

	// Maximum number of reconnection attempts
	maxReconnectAttempts = 5

	// Initial backoff delay
	initialBackoff = 1 * time.Second

	// Maximum backoff delay
	maxBackoff = 30 * time.Second

	maxRetryAttempts = 3
	retryDelay       = 500 * time.Millisecond
	messageQueueSize = 100
)

type MessageItem struct {
	data    []byte
	retries int
	created time.Time
}

type Subscription struct {
	Type      string                 `json:"type"`
	Addresses []string               `json:"addresses,omitempty"`
	Options   map[string]interface{} `json:"options,omitempty"`
}

// Add ConnectionStatus struct
type ConnectionStatus struct {
	Address         string    `json:"address"`
	Connected       bool      `json:"connected"`
	LastConnected   time.Time `json:"lastConnected"`
	ReconnectCount  int       `json:"reconnectCount"`
	QueueSize       int       `json:"queueSize"`
	IsReconnecting  bool      `json:"isReconnecting"`
	LastMessageSent time.Time `json:"lastMessageSent"`
}
