package chain

import (
	"container/list"
	"errors"
	"log"
	"sync"

	"github.com/thrylos-labs/thrylos/shared"
)

type txPool struct {
	mu           sync.RWMutex
	transactions map[string]*list.Element
	order        *list.List
}

type txEntry struct {
	txID string
	tx   *shared.Transaction
}

// NewTxPool creates a new transaction pool
func NewTxPool() *txPool {
	return &txPool{
		transactions: make(map[string]*list.Element),
		order:        list.New(),
	}
}

// AddTransaction adds a transaction to the pool
func (p *txPool) AddTransaction(tx *shared.Transaction) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.transactions[tx.ID]; exists {
		return errors.New("transaction already exists in the pool")
	}

	entry := &txEntry{txID: tx.ID, tx: tx}
	element := p.order.PushBack(entry)
	p.transactions[tx.ID] = element
	return nil
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
