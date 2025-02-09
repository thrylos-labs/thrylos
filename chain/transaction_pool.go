package chain

import (
	"errors"
	"log"
	"sync"

	"github.com/thrylos-labs/thrylos/shared"
)

type txPool struct {
	mu           sync.RWMutex
	transactions map[string]*shared.Transaction
}

// NewTxPool creates a new transaction pool
func NewTxPool() *txPool {
	log.Println("Creating a new transaction pool")
	return &txPool{
		transactions: make(map[string]*shared.Transaction),
	}
}

// AddTransaction adds a transaction to the pool
func (p *txPool) AddTransaction(tx *shared.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.transactions[tx.ID]; exists {
		log.Printf("Transaction %s already exists in the pool", tx.ID)
		return errors.New("transaction already exists in the pool")
	}

	p.transactions[tx.ID] = tx
	log.Printf("Transaction %s added to the pool", tx.ID)
	return nil
}

// RemoveTransaction removes a transaction from the pool
func (p *txPool) RemoveTransaction(tx *shared.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.transactions[tx.ID]; !exists {
		log.Printf("Transaction %s not found in the pool", tx.ID)
		return errors.New("transaction not found in the pool")
	}

	delete(p.transactions, tx.ID)
	log.Printf("Transaction %s removed from the pool", tx.ID)
	return nil
}

// GetTransaction retrieves a transaction from the pool by its ID
func (p *txPool) GetTransaction(txID string) (*shared.Transaction, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	tx, exists := p.transactions[txID]
	if !exists {
		log.Printf("Transaction %s not found in the pool", txID)
		return nil, errors.New("transaction not found in the pool")
	}

	log.Printf("Transaction %s retrieved from the pool", txID)
	return tx, nil
}

// GetAllTransactions retrieves all transactions from the pool
func (p *txPool) GetAllTransactions() ([]*shared.Transaction, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	txs := make([]*shared.Transaction, 0, len(p.transactions))
	for _, tx := range p.transactions {
		txs = append(txs, tx)
	}

	log.Printf("Retrieved all transactions from the pool, count: %d", len(txs))
	return txs, nil
}

// BroadcastTransaction broadcasts a transaction to the network
func (p *txPool) BroadcastTransaction(tx *shared.Transaction) error {
	// Broadcast the transaction to the network, will be implemented, e.g by transmisstig the transaction through the channel.
	log.Printf("Broadcasting transaction %s to the network", tx.ID)
	return nil
}

// Size returns the number of transactions in the pool
func (p *txPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	size := len(p.transactions)
	log.Printf("Transaction pool size: %d", size)
	return size
}
