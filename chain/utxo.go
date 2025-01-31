package chain

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/btcsuite/btcutil/bech32"
	lru "github.com/hashicorp/golang-lru"
	"github.com/thrylos-labs/thrylos"
	"github.com/willf/bloom"
)

// UTXO represents an Unspent Transaction Output, which is the output of a blockchain transaction
// that has not been spent and can be used as an input in a new transaction. UTXOs are fundamental
// to understanding a user's balance within the blockchain.
type UTXO struct {
	ID            string `json:"id,omitempty"`
	TransactionID string `json:"transaction_id"` // Changed from transactionid
	Index         int    `json:"index"`
	OwnerAddress  string `json:"owner_address"` // Already correct
	Amount        int64  `json:"amount"`
	IsSpent       bool   `json:"is_spent"` // Changed from isspent
}

func validateBech32Address(address string) bool {
	_, _, err := bech32.Decode(address)
	return err == nil
}

// ValidateUTXO checks for the validity of the UTXO, ensuring its data conforms to expected formats and rules.
func (u *UTXO) ValidateUTXO() error {
	// Check if the owner address is correctly formatted
	if !validateBech32Address(u.OwnerAddress) {
		return fmt.Errorf("invalid owner address format: %s", u.OwnerAddress)
	}
	// Further validation rules can be added here
	return nil
}

var AllUTXOs []UTXO

func GetAllUTXOs() map[string]UTXO {
	allUTXOs := make(map[string]UTXO)
	// Example data population, replace with actual data retrieval logic
	for _, utxo := range AllUTXOs {
		key := fmt.Sprintf("%s-%d", utxo.TransactionID, utxo.Index)
		allUTXOs[key] = utxo
	}
	return allUTXOs
}

type UTXOCache struct {
	cache *lru.Cache
	mu    sync.Mutex
	bf    *bloom.BloomFilter
}

func NewUTXOCache(size int, bloomSize uint, falsePositiveRate float64) (*UTXOCache, error) {
	c, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	bf := bloom.NewWithEstimates(bloomSize, falsePositiveRate)
	return &UTXOCache{cache: c, bf: bf}, nil
}

func (uc *UTXOCache) Get(key string) (*UTXO, bool) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	if !uc.bf.TestString(key) {
		return nil, false
	}
	value, ok := uc.cache.Get(key)
	if !ok {
		return nil, false
	}
	return value.(*UTXO), true
}

func (uc *UTXOCache) Add(key string, utxo *UTXO) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.cache.Add(key, utxo)
	uc.bf.AddString(key)
}

func (uc *UTXOCache) Remove(key string) {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.cache.Remove(key)
}

// ConvertSharedUTXOToProto converts a shared.UTXO to a protobuf UTXO message.
func ConvertSharedUTXOToProto(u UTXO) *thrylos.UTXO {
	return &thrylos.UTXO{
		TransactionId: u.TransactionID,
		Index:         int32(u.Index),
		OwnerAddress:  u.OwnerAddress,
		Amount:        int64(u.Amount),
	}
}

// GetUTXOsForUser scans through all available UTXOs and returns those owned by a specific user.
// This function is crucial for determining a user's spendable balance.
func GetUTXOsForUser(user string, allUTXOs map[string]UTXO) []UTXO {
	var userUTXOs []UTXO
	for _, utxo := range allUTXOs {
		if utxo.OwnerAddress == user {
			userUTXOs = append(userUTXOs, utxo)
		}
	}
	return userUTXOs
}

// Assuming the UTXOCache is a global variable or accessible somehow in your server structure
var globalUTXOCache *UTXOCache

// GetUTXO retrieves a UTXO by its key.
func GetUTXO(txID string, index int) (*UTXO, error) {
	key := fmt.Sprintf("%s-%d", txID, index)
	utxo, exists := globalUTXOCache.Get(key)
	if !exists {
		return nil, fmt.Errorf("UTXO not found")
	}
	return utxo, nil
}

// MarshalJSON customizes the JSON representation of the UTXO struct. This can be useful for
// excluding certain fields from the JSON output or adding extra metadata when UTXOs are serialized.
func (u UTXO) MarshalJSON() ([]byte, error) {
	type Alias UTXO
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(&u),
	})
}

// CreateUTXO initializes a new UTXO with the specified attributes. This function is typically
// called when a transaction is processed, and its outputs are being determined.
func CreateUTXO(id, txID string, index int, owner string, amount int64) UTXO {
	fmt.Printf("Creating UTXO with ID: %s, TransactionID: %s, Index: %d, Owner: %s, Amount: %d\n", id, txID, index, owner, amount)
	return UTXO{
		ID:            id,
		TransactionID: txID,
		Index:         index,
		OwnerAddress:  owner,
		Amount:        amount,
	}
}

// This utilizes the custom MarshalJSON method defined in the UTXO struct if present.
func SerializeUTXOs(utxos []UTXO) ([]byte, error) {
	return json.Marshal(utxos)
}

// MarkUTXOAsSpent removes a UTXO from the set of available UTXOs, effectively marking it as spent.
// This operation is critical in preventing double-spending within the blockchain system.
func MarkUTXOAsSpent(utxoID string, allUTXOs map[string]UTXO) {
	delete(allUTXOs, utxoID)
}
