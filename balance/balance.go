package balance

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/config"
	"github.com/thrylos-labs/thrylos/types"
)

type Manager struct {
	messageBus     types.MessageBusInterface // Change to interface from types
	notifier       types.BalanceNotifier
	cache          sync.Map
	cacheTTL       time.Duration
	pendingUpdates map[string][]types.PendingBalanceUpdate
	pendingMutex   sync.RWMutex
	updateQueue    *BalanceUpdateQueue
}

func NewManager(messageBus types.MessageBusInterface, notifier types.BalanceNotifier) *Manager {
	m := &Manager{
		messageBus:     messageBus,
		notifier:       notifier,
		cacheTTL:       5 * time.Second,
		pendingUpdates: make(map[string][]types.PendingBalanceUpdate),
	}
	m.updateQueue = newBalanceUpdateQueue(m)

	// Subscribe to relevant message types
	ch := make(chan types.Message, 100)
	messageBus.Subscribe(types.GetBalance, ch)

	// Start message handler
	go m.handleMessages(ch)

	return m
}

// Add this to the balance package for mock only
func NewBalanceUpdateQueue() *BalanceUpdateQueue {
	return &BalanceUpdateQueue{
		queue: make(chan types.BalanceUpdateRequest, 1000),
	}
}

func (m *Manager) handleMessages(ch chan types.Message) {
	for msg := range ch {
		switch msg.Type {
		case types.GetBalance:
			if address, ok := msg.Data.(string); ok {
				balance, err := m.GetBalance(address)
				msg.ResponseCh <- types.Response{
					Data:  balance,
					Error: err,
				}
			} else {
				msg.ResponseCh <- types.Response{
					Error: fmt.Errorf("invalid address format in message"),
				}
			}
		}
	}
}

func (m *Manager) SendBalanceUpdate(address string) error {
	return m.notifier.SendBalanceUpdate(address)
}

func (m *Manager) NotifyBalanceUpdate(address string, balance amount.Amount) {
	m.notifier.NotifyBalanceUpdate(address, balance)
}

type cachedBalance struct {
	value     amount.Amount
	timestamp time.Time
}

type BalanceUpdateQueue struct {
	queue   chan types.BalanceUpdateRequest
	manager *Manager
}

// Add this to the balance package
func (q *BalanceUpdateQueue) QueueUpdate(req types.BalanceUpdateRequest) {
	q.queue <- req
}

func newBalanceUpdateQueue(manager *Manager) *BalanceUpdateQueue {
	return &BalanceUpdateQueue{
		queue:   make(chan types.BalanceUpdateRequest, 1000),
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

func (m *Manager) GetBalance(address string) (amount.Amount, error) {
	// Check cache first
	if cached, ok := m.cache.Load(address); ok {
		cachedBal := cached.(cachedBalance)
		if time.Since(cachedBal.timestamp) < m.cacheTTL {
			return cachedBal.value, nil
		}
	}

	// Request UTXOs through message bus
	responseCh := make(chan types.Response)
	m.messageBus.Publish(types.Message{
		Type: types.GetUTXOs,
		Data: types.UTXORequest{
			Address: address,
		},
		ResponseCh: responseCh,
	})

	// Wait for response
	response := <-responseCh
	if response.Error != nil {
		return 0, response.Error
	}

	utxos, ok := response.Data.([]types.UTXO)
	if !ok {
		return 0, fmt.Errorf("invalid UTXO response format")
	}

	var total amount.Amount
	for _, utxo := range utxos {
		if !utxo.IsSpent {
			total += utxo.Amount
		}
	}

	if total == 0 {
		initialBalanceThrylos := 70.0
		initialBalanceNano, _ := amount.NewAmount(initialBalanceThrylos)

		newUtxo := types.UTXO{
			OwnerAddress:  address,
			Amount:        initialBalanceNano,
			TransactionID: fmt.Sprintf("genesis-%s", address),
			IsSpent:       false,
			Index:         0,
		}

		// Add UTXO through message bus
		addUTXOResponse := make(chan types.Response)
		m.messageBus.Publish(types.Message{
			Type: types.AddUTXO,
			Data: types.AddUTXORequest{
				UTXO: newUtxo,
			},
			ResponseCh: addUTXOResponse,
		})

		if response := <-addUTXOResponse; response.Error != nil {
			return 0, response.Error
		}

		total = initialBalanceNano
	}

	// Update cache
	m.cache.Store(address, cachedBalance{
		value:     total,
		timestamp: time.Now(),
	})

	// Update state through message bus
	m.messageBus.Publish(types.Message{
		Type: types.UpdateState,
		Data: types.UpdateStateRequest{
			Address: address,
			Balance: int64(total), // Cast to int64
		},
		ResponseCh: make(chan types.Response),
	})

	return total, nil
}

func (m *Manager) AddPendingBalanceUpdate(address string, balance int64) {
	m.pendingMutex.Lock()
	defer m.pendingMutex.Unlock()
	m.pendingUpdates[address] = append(m.pendingUpdates[address], types.PendingBalanceUpdate{
		Address:   address,
		Balance:   balance,
		Timestamp: time.Now(),
	})
	log.Printf("Added pending balance update for address %s: %d nanoTHRYLOS", address, balance)
}

func (m *Manager) GetPendingBalanceUpdates(address string) []types.PendingBalanceUpdate {
	m.pendingMutex.RLock()
	defer m.pendingMutex.RUnlock()
	return m.pendingUpdates[address]
}

func (m *Manager) RemovePendingBalanceUpdate(address string, update types.PendingBalanceUpdate) {
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
	return int64(thrylos * 1e9)
}
