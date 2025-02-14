package shared

import (
	"sync"

	"github.com/thrylos-labs/thrylos/types"
)

// MessageBus implementation
type MessageBus struct {
	subscribers map[types.MessageType][]chan types.Message
	mu          sync.RWMutex
}

// Global message bus instance
var (
	globalMessageBus *MessageBus
	once             sync.Once
)

// GetMessageBus returns the singleton message bus instance
func GetMessageBus() *MessageBus {
	once.Do(func() {
		globalMessageBus = &MessageBus{
			subscribers: make(map[types.MessageType][]chan types.Message),
		}
	})
	return globalMessageBus
}

// NewMessageBus creates a new message bus (for testing purposes)
func NewMessageBus() *MessageBus {
	return &MessageBus{
		subscribers: make(map[types.MessageType][]chan types.Message),
	}
}

// Subscribe to specific message types
func (mb *MessageBus) Subscribe(msgType types.MessageType, ch chan types.Message) {
	mb.mu.Lock()
	defer mb.mu.Unlock()
	mb.subscribers[msgType] = append(mb.subscribers[msgType], ch)
}

// Unsubscribe from a message type
func (mb *MessageBus) Unsubscribe(msgType types.MessageType, ch chan types.Message) {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	subscribers := mb.subscribers[msgType]
	for i, subscriber := range subscribers {
		if subscriber == ch {
			mb.subscribers[msgType] = append(subscribers[:i], subscribers[i+1:]...)
			break
		}
	}
}

// Publish a message to all subscribers
func (mb *MessageBus) Publish(msg types.Message) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	if subscribers, ok := mb.subscribers[msg.Type]; ok {
		for _, ch := range subscribers {
			go func(c chan types.Message) {
				c <- msg
			}(ch)
		}
	}
}

// Close closes all subscriber channels and cleans up resources
func (mb *MessageBus) Close() {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	// Close all subscriber channels
	for msgType, subscribers := range mb.subscribers {
		for _, ch := range subscribers {
			close(ch)
		}
		delete(mb.subscribers, msgType)
	}
}
