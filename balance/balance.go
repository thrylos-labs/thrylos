package balance

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/thrylos-labs/thrylos/shared"

	"github.com/thrylos-labs/thrylos/config"
)

// NEED TO ADD MESSAGES TO MESSAGES.GO FOR BALANCE
// SO IT CAN USE NODE.GO

type BalanceNotifier interface {
	SendBalanceUpdate(address string) error
	NotifyBalanceUpdate(address string, balance int64)
}

type Manager struct {
	// node           *node.Node
	notifier       BalanceNotifier
	cache          sync.Map
	cacheTTL       time.Duration
	pendingUpdates map[string][]PendingBalanceUpdate
	pendingMutex   sync.RWMutex
	updateQueue    *BalanceUpdateQueue
}

// func NewManager(node *node.Node, notifier BalanceNotifier) *Manager {
// 	m := &Manager{
// 		node:           node,
// 		notifier:       notifier,
// 		cacheTTL:       5 * time.Second,
// 		pendingUpdates: make(map[string][]PendingBalanceUpdate),
// 	}
// 	m.updateQueue = newBalanceUpdateQueue(m)
// 	return m
// }

func (m *Manager) SendBalanceUpdate(address string) error {
	return m.notifier.SendBalanceUpdate(address)
}

func (m *Manager) NotifyBalanceUpdate(address string, balance int64) {
	m.notifier.NotifyBalanceUpdate(address, balance)
}

type cachedBalance struct {
	value     int64
	timestamp time.Time
}

type BalanceUpdateRequest struct {
	Address string
	Retries int
}

type PendingBalanceUpdate struct {
	Address   string
	Balance   int64
	Timestamp time.Time
}

type BalanceUpdateQueue struct {
	queue   chan BalanceUpdateRequest
	manager *Manager
}

func newBalanceUpdateQueue(manager *Manager) *BalanceUpdateQueue {
	return &BalanceUpdateQueue{
		queue:   make(chan BalanceUpdateRequest, 1000),
		manager: manager,
	}
}

func (q *BalanceUpdateQueue) balanceUpdateWorker() {
	for req := range q.queue {
		success := false
		for attempt := 0; attempt < req.Retries && !success; attempt++ {
			if err := q.manager.SendBalanceUpdate(req.Address); err == nil {
				success = true
			} else {
				log.Printf("Failed to update balance for %s, attempt %d: %v", req.Address, attempt+1, err)
				time.Sleep(time.Duration(math.Pow(2, float64(attempt))) * time.Second)
			}
		}
		if !success {
			log.Printf("Failed to update balance for %s after %d attempts", req.Address, req.Retries)
		}
	}
}

func (m *Manager) GetBalance(address string) (int64, error) {
	// Check cache first
	if cached, ok := m.checkCache(address); ok {
		return cached, nil
	}

	// Get UTXOs through message system
	utxoResponseCh := make(chan shared.Response)
	shared.GetMessageBus().Publish(shared.Message{
		Type: shared.GetUTXOs,
		Data: shared.UTXORequest{
			Address: address,
		},
		ResponseCh: utxoResponseCh,
	})

	// Wait for response
	utxoResponse := <-utxoResponseCh
	if utxoResponse.Error != nil {
		return 0, utxoResponse.Error
	}

	utxos := utxoResponse.Data.([]shared.UTXO)

	// Calculate total from UTXOs
	var total int64
	for _, utxo := range utxos {
		if !utxo.IsSpent {
			total += utxo.Amount
		}
	}

	// Handle genesis balance if total is 0
	if total == 0 {
		initialBalanceThrylos := 70.0
		initialBalanceNano := ThrylosToNano(initialBalanceThrylos)

		newUtxo := shared.UTXO{
			OwnerAddress:  address,
			Amount:        initialBalanceNano,
			TransactionID: fmt.Sprintf("genesis-%s", address),
			IsSpent:       false,
			Index:         0,
		}

		// Add UTXO through message system
		addUTXOResponseCh := make(chan shared.Response)
		shared.GetMessageBus().Publish(shared.Message{
			Type: shared.AddUTXO,
			Data: shared.AddUTXORequest{
				UTXO: newUtxo,
			},
			ResponseCh: addUTXOResponseCh,
		})

		// Wait for response
		addUTXOResponse := <-addUTXOResponseCh
		if addUTXOResponse.Error != nil {
			return 0, addUTXOResponse.Error
		}

		total = initialBalanceNano
	}

	// Update cache
	m.cache.Store(address, cachedBalance{
		value:     total,
		timestamp: time.Now(),
	})

	// Update state through message system
	shared.GetMessageBus().Publish(shared.Message{
		Type: shared.UpdateState,
		Data: shared.UpdateStateRequest{
			Address: address,
			Balance: total,
		},
		ResponseCh: make(chan shared.Response),
	})

	return total, nil
}

func (m *Manager) checkCache(address string) (int64, bool) {
	if cached, ok := m.cache.Load(address); ok {
		cachedBal := cached.(cachedBalance)
		if time.Since(cachedBal.timestamp) < m.cacheTTL {
			return cachedBal.value, true
		}
	}
	return 0, false
}

func (m *Manager) AddPendingBalanceUpdate(address string, balance int64) {
	m.pendingMutex.Lock()
	defer m.pendingMutex.Unlock()
	m.pendingUpdates[address] = append(m.pendingUpdates[address], PendingBalanceUpdate{
		Address:   address,
		Balance:   balance,
		Timestamp: time.Now(),
	})
	log.Printf("Added pending balance update for address %s: %d nanoTHRYLOS", address, balance)
}

func (m *Manager) GetPendingBalanceUpdates(address string) []PendingBalanceUpdate {
	m.pendingMutex.RLock()
	defer m.pendingMutex.RUnlock()
	return m.pendingUpdates[address]
}

func (m *Manager) RemovePendingBalanceUpdate(address string, update PendingBalanceUpdate) {
	m.pendingMutex.Lock()
	defer m.pendingMutex.Unlock()
	updates := m.pendingUpdates[address]
	for i, u := range updates {
		if u.Timestamp == update.Timestamp {
			m.pendingUpdates[address] = append(updates[:i], updates[i+1:]...)
			break
		}
	}
}

func (m *Manager) ProcessPendingBalanceUpdates(address string) {
	m.pendingMutex.Lock()
	pendingUpdates, exists := m.pendingUpdates[address]
	if exists {
		delete(m.pendingUpdates, address)
	}
	m.pendingMutex.Unlock()

	if exists {
		log.Printf("Processing %d pending balance updates for address %s", len(pendingUpdates), address)
		for _, update := range pendingUpdates {
			if err := m.SendBalanceUpdate(address); err != nil {
				log.Printf("Error processing pending balance update for address %s: %v", address, err)
			} else {
				log.Printf("Processed pending balance update for address %s: %d nanoTHRYLOS", address, update.Balance)
			}
		}
	}
}

func (m *Manager) HandleBalanceUpdate(address string) {
	if err := m.SendBalanceUpdate(address); err != nil {
		log.Printf("Failed to send balance update for %s: %v", address, err)
	} else {
		balance, _ := m.GetBalance(address)
		log.Printf("Successfully sent balance update for %s. Current balance: %d nanoTHRYLOS",
			address, balance)
	}
}

func (m *Manager) ProcessBalanceUpdateQueue() {
	for request := range m.updateQueue.queue {
		balance, err := m.GetBalance(request.Address)
		if err != nil {
			log.Printf("Error processing balance update for %s: %v", request.Address, err)
			continue
		}
		m.NotifyBalanceUpdate(request.Address, balance)
	}
}

func (m *Manager) UpdateBalanceAsync(address string) {
	go func() {
		retries := 0
		maxRetries := 5
		for retries < maxRetries {
			balance, err := m.GetBalance(address)
			if err != nil {
				log.Printf("Error getting balance for %s: %v", address, err)
				retries++
				time.Sleep(time.Duration(math.Pow(2, float64(retries))) * time.Second)
				continue
			}

			if err := m.SendBalanceUpdate(address); err == nil {
				log.Printf("Balance updated successfully for %s: %d", address, balance)
				return
			}
			retries++
			time.Sleep(time.Duration(math.Pow(2, float64(retries))) * time.Second)
		}
		log.Printf("Failed to update balance for %s after %d attempts", address, maxRetries)
	}()
}

// Start and Stop methods for the manager
func (m *Manager) Start() {
	go m.updateQueue.balanceUpdateWorker()
}

func (m *Manager) Stop() {
	close(m.updateQueue.queue)
}

// Utility functions
func FormatBalance(balanceNano int64) string {
	balanceThrylos := float64(balanceNano) / config.NanoPerThrylos
	return fmt.Sprintf("%d nanoTHRYLOS (%.7f THRYLOS)", balanceNano, balanceThrylos)
}

func ThrylosToNano(thrylos float64) int64 {
	return int64(thrylos * config.NanoPerThrylos)
}
