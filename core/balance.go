package core

import (
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/thrylos-labs/thrylos/shared"
)

const (
	NanoThrylosPerThrylos    = 1e7
	NANO_THRYLOS_PER_THRYLOS = 1e7 // Consider removing this duplicate constant
)

var (
	balanceCache               sync.Map
	cacheTTL                   = 5 * time.Second
	pendingBalanceUpdates      = make(map[string][]PendingBalanceUpdate)
	pendingBalanceUpdatesMutex sync.RWMutex
)

// Types for balance management
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
	queue chan BalanceUpdateRequest
	node  *Node
}

// Create new balance update queue
func newBalanceUpdateQueue(node *Node) *BalanceUpdateQueue {
	return &BalanceUpdateQueue{
		queue: make(chan BalanceUpdateRequest, 1000),
		node:  node,
	}
}

// Balance queue worker
func (q *BalanceUpdateQueue) balanceUpdateWorker() {
	for req := range q.queue {
		success := false
		for attempt := 0; attempt < req.Retries && !success; attempt++ {
			if err := q.node.SendBalanceUpdate(req.Address); err == nil {
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

// Core balance methods
func (node *Node) GetBalance(address string) (int64, error) {
	// Always recalculate from UTXOs first
	utxos, err := node.Blockchain.GetUTXOsForAddress(address)
	if err != nil {
		return 0, err
	}

	var total int64
	for _, utxo := range utxos {
		if !utxo.IsSpent {
			total += utxo.Amount
		}
	}

	// If no UTXOs exist, create initial balance of 70 Thrylos
	if total == 0 {
		initialBalance := int64(700000000) // 70 Thrylos in nanoTHR

		// Create initial UTXO
		newUtxo := shared.UTXO{
			OwnerAddress:  address,
			Amount:        initialBalance,
			TransactionID: fmt.Sprintf("genesis-%s", address),
			IsSpent:       false,
			Index:         0,
		}

		if err := node.Blockchain.Database.AddUTXO(newUtxo); err != nil {
			return 0, err
		}

		total = initialBalance
	}

	// Update caches
	balanceCache.Store(address, cachedBalance{
		value:     total,
		timestamp: time.Now(),
	})
	node.Blockchain.StateManager.UpdateState(address, total, nil)

	return total, nil
}

// Pending balance management
func (node *Node) AddPendingBalanceUpdate(address string, balance int64) {
	pendingBalanceUpdatesMutex.Lock()
	defer pendingBalanceUpdatesMutex.Unlock()
	pendingBalanceUpdates[address] = append(pendingBalanceUpdates[address], PendingBalanceUpdate{
		Address:   address,
		Balance:   balance,
		Timestamp: time.Now(),
	})
	log.Printf("Added pending balance update for address %s: %d nanoTHRYLOS", address, balance)
}

func (node *Node) GetPendingBalanceUpdates(address string) []PendingBalanceUpdate {
	pendingBalanceUpdatesMutex.RLock()
	defer pendingBalanceUpdatesMutex.RUnlock()
	return pendingBalanceUpdates[address]
}

func (node *Node) RemovePendingBalanceUpdate(address string, update PendingBalanceUpdate) {
	pendingBalanceUpdatesMutex.Lock()
	defer pendingBalanceUpdatesMutex.Unlock()
	updates := pendingBalanceUpdates[address]
	for i, u := range updates {
		if u.Timestamp == update.Timestamp {
			pendingBalanceUpdates[address] = append(updates[:i], updates[i+1:]...)
			break
		}
	}
}

func (node *Node) ProcessPendingBalanceUpdates(address string) {
	pendingBalanceUpdatesMutex.Lock()
	pendingUpdates, exists := pendingBalanceUpdates[address]
	if exists {
		delete(pendingBalanceUpdates, address)
	}
	pendingBalanceUpdatesMutex.Unlock()

	if exists {
		log.Printf("Processing %d pending balance updates for address %s", len(pendingUpdates), address)
		for _, update := range pendingUpdates {
			if err := node.SendBalanceUpdate(address); err != nil {
				log.Printf("Error processing pending balance update for address %s: %v", address, err)
			} else {
				log.Printf("Processed pending balance update for address %s: %d nanoTHRYLOS", address, update.Balance)
			}
		}
	}
}

// Balance update methods
func (node *Node) handleBalanceUpdate(address string) {
	if err := node.SendBalanceUpdate(address); err != nil {
		log.Printf("Failed to send balance update for %s: %v", address, err)
	} else {
		balance, _ := node.GetBalance(address)
		log.Printf("Successfully sent balance update for %s. Current balance: %d nanoTHRYLOS",
			address, balance)
	}
}

func (n *Node) processBalanceUpdateQueue() {
	for request := range n.balanceUpdateQueue.queue {
		balance, err := n.GetBalance(request.Address)
		if err != nil {
			log.Printf("Error processing balance update for %s: %v", request.Address, err)
			continue
		}
		n.notifyBalanceUpdate(request.Address, balance)
	}
}

func (node *Node) UpdateBalanceAsync(address string) {
	go func() {
		retries := 0
		maxRetries := 5
		for retries < maxRetries {
			balance, err := node.Blockchain.GetBalance(address)
			if err != nil {
				log.Printf("Error getting balance for %s: %v", address, err)
				retries++
				time.Sleep(time.Duration(math.Pow(2, float64(retries))) * time.Second)
				continue
			}

			if err := node.SendBalanceUpdate(address); err == nil {
				log.Printf("Balance updated successfully for %s: %d", address, balance)
				return
			}
			retries++
			time.Sleep(time.Duration(math.Pow(2, float64(retries))) * time.Second)
		}
		log.Printf("Failed to update balance for %s after %d attempts", address, maxRetries)
	}()
}

// Utility functions for balance formatting
func formatBalance(balanceNano int64) string {
	balanceThrylos := float64(balanceNano) / NanoThrylosPerThrylos
	return fmt.Sprintf("%d nanoTHRYLOS (%.7f THRYLOS)", balanceNano, balanceThrylos)
}

func ThrylosToNanoNode(thrylos float64) int64 {
	return int64(thrylos * NanoThrylosPerThrylos)
}
