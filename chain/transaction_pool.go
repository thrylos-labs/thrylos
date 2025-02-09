package chain

import (
	"container/list"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/thrylos-labs/thrylos/network"
	"github.com/thrylos-labs/thrylos/shared"
	"github.com/thrylos-labs/thrylos/store"
)

// Holds pending transactions before they're added to blocks

type txPool struct {
	mu           sync.RWMutex
	transactions map[string]*list.Element
	order        *list.List
	db           *shared.Store                  // Add database reference
	propagator   *network.TransactionPropagator // Add propagator
}

type txEntry struct {
	txID string
	tx   *shared.Transaction
}

// NewTxPool creates a new transaction pool
func NewTxPool(db *store.Database, propagator *network.TransactionPropagator) *txPool {
	return &txPool{
		transactions: make(map[string]*list.Element),
		order:        list.New(),
		db:           &db.Blockchain,
		propagator:   propagator,
	}
}

// AddTransaction adds a transaction to the pool
// func (p *txPool) AddTransaction(tx *shared.Transaction) error {
// 	p.mu.Lock()
// 	defer p.mu.Unlock()

// 	// Check for existing transaction
// 	if _, exists := p.transactions[tx.ID]; exists {
// 		return errors.New("transaction already exists in the pool")
// 	}

// 	// Generate and set salt if not present
// 	if len(tx.Salt) == 0 {
// 		salt, err := generateSalt()
// 		if err != nil {
// 			return fmt.Errorf("failed to generate salt: %v", err)
// 		}
// 		tx.Salt = salt
// 	}

// 	// Verify salt uniqueness
// 	if err := p.verifyTransactionUniqueness(tx); err != nil {
// 		return fmt.Errorf("transaction salt verification failed: %v", err)
// 	}

// 	// Propagate to validators
// 	if err := p.propagator.PropagateTransaction(tx); err != nil {
// 		return fmt.Errorf("failed to propagate transaction: %v", err)
// 	}
// 	log.Printf("Transaction %s propagated to all validators", tx.ID)

// 	// Start database transaction
// 	dbTx, err := shared.Store.BeginTransaction()
// 	if err != nil {
// 		return fmt.Errorf("failed to begin transaction: %v", err)
// 	}
// 	defer shared.Store.RollbackTransaction(dbTx)

// 	// Store transaction with salt
// 	txKey := []byte("transaction-" + tx.ID)
// 	tx.Status = "pending"
// 	txJSON, err := json.Marshal(tx)
// 	if err != nil {
// 		return fmt.Errorf("error marshaling transaction: %v", err)
// 	}

// 	if err := shared.StoreSetTransaction(dbTx, txKey, txJSON); err != nil {
// 		return fmt.Errorf("error storing transaction: %v", err)
// 	}

// 	if err := shared.Store.CommitTransaction(dbTx); err != nil {
// 		return fmt.Errorf("error committing transaction: %v", err)
// 	}

// 	// Add to pool
// 	entry := &txEntry{txID: tx.ID, tx: tx}
// 	element := p.order.PushBack(entry)
// 	p.transactions[tx.ID] = element

// 	log.Printf("Transaction %s with salt added to pool. Total in pool: %d",
// 		tx.ID, p.order.Len())

// 	return nil
// }

// // // // Helper function to verify transaction uniqueness using salt
// func (p *txPool) verifyTransactionUniqueness(tx *shared.Transaction) error {
// 	if tx == nil {
// 		return fmt.Errorf("nil transaction")
// 	}
// 	if len(tx.Salt) == 0 {
// 		return fmt.Errorf("empty salt")
// 	}
// 	if len(tx.Salt) != 32 {
// 		return fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
// 	}

// 	// Use the efficient helper function to check salt uniqueness
// 	if BlockchainImpl.checkSaltInBlocks(tx.Salt) {
// 		return fmt.Errorf("duplicate salt detected: transaction replay attempt")
// 	}

// 	return nil
// }

// Additional helper methods as needed
func (p *txPool) GetTransactionStatus(txID string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if elem, exists := p.transactions[txID]; exists {
		entry := elem.Value.(*txEntry)
		return entry.tx.Status, nil
	}
	return "", fmt.Errorf("transaction not found")
}

func (p *txPool) UpdateTransactionStatus(txID string, status string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if elem, exists := p.transactions[txID]; exists {
		entry := elem.Value.(*txEntry)
		entry.tx.Status = status
		return nil
	}
	return fmt.Errorf("transaction not found")
}

// RemoveTransaction removes a transaction from the pool
func (p *txPool) RemoveTransaction(tx *shared.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	element, exists := p.transactions[tx.ID]
	if !exists {
		log.Printf("Transaction %s not found in the pool", tx.ID)
		return errors.New("transaction not found in the pool")
	}

	p.order.Remove(element)
	delete(p.transactions, tx.ID)
	log.Printf("Transaction %s removed from the pool", tx.ID)
	return nil
}

// GetTransaction retrieves a transaction from the pool by its ID
func (p *txPool) GetTransaction(txID string) (*shared.Transaction, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	element, exists := p.transactions[txID]
	if !exists {
		log.Printf("Transaction %s not found in the pool", txID)
		return nil, errors.New("transaction not found in the pool")
	}

	entry := element.Value.(*txEntry)
	log.Printf("Transaction %s retrieved from the pool", txID)
	return entry.tx, nil
}

// GetFirstTransaction retrieves the first transaction added to the pool
func (p *txPool) GetFirstTransaction() (*shared.Transaction, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.order.Len() == 0 {
		return nil, errors.New("no transactions in the pool")
	}

	firstElement := p.order.Front()
	entry := firstElement.Value.(*txEntry)
	return entry.tx, nil
}

// GetAllTransactions retrieves all transactions from the pool
func (p *txPool) GetAllTransactions() ([]*shared.Transaction, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	txs := make([]*shared.Transaction, 0, p.order.Len())
	for e := p.order.Front(); e != nil; e = e.Next() {
		entry := e.Value.(*txEntry)
		txs = append(txs, entry.tx)
	}

	log.Printf("Retrieved all transactions from the pool, count: %d", len(txs))
	return txs, nil
}

// BroadcastTransaction broadcasts a transaction to the network
func (p *txPool) BroadcastTransaction(tx *shared.Transaction) error {
	// Broadcast the transaction to the network, will be implemented, e.g by transmitting the transaction through the channel.
	log.Printf("Broadcasting transaction %s to the network", tx.ID)
	return nil
}

// Size returns the number of transactions in the pool
func (p *txPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.order.Len()
}
