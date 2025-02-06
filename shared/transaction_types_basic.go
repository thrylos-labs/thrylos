// Package shared contains the Transaction type definition and basic methods.
//
// Transaction is placed in the shared package because:
// 1. It's a fundamental data structure used by multiple packages (balance, chain, node)
// 2. Having it here prevents circular dependencies between packages
// 3. It contains the core transaction structure and basic validation logic
//
// Think of Transactions like contracts - while many parts of the system need to read
// and verify the contract (shared package), the actual processing and execution happens
// in a specific department (chain package).

package shared

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3" // Update to v3

	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/utils"
)

// Transaction defines the structure for blockchain transactions
type Transaction struct {
	ID               string           `cbor:"1,keyasint"`
	Timestamp        int64            `cbor:"2,keyasint"`
	Inputs           []UTXO           `cbor:"3,keyasint"`
	Outputs          []UTXO           `cbor:"4,keyasint"`
	EncryptedInputs  []byte           `cbor:"5,keyasint,omitempty"`
	EncryptedOutputs []byte           `cbor:"6,keyasint,omitempty"`
	EncryptedAESKey  []byte           `cbor:"7,keyasint"`
	PreviousTxIds    []string         `cbor:"8,keyasint"`
	SenderAddress    address.Address  `cbor:"9,keyasint"`
	SenderPublicKey  crypto.PublicKey `cbor:"10,keyasint"`
	Signature        crypto.Signature `cbor:"11,keyasint,omitempty"`
	GasFee           int              `cbor:"12,keyasint"`
	BlockHash        string           `cbor:"13,keyasint,omitempty"`
	Salt             []byte           `cbor:"14,keyasint,omitempty"`
	Status           string           `cbor:"15,keyasint,omitempty"`
}

// NewTransaction creates a new Transaction instance
func NewTransaction(id string, inputs, outputs []UTXO) *Transaction {
	return &Transaction{
		ID:        id,
		Inputs:    inputs,
		Outputs:   outputs,
		Timestamp: time.Now().Unix(),
	}
}

// Basic validation of transaction fields
func (tx *Transaction) Validate() error {
	if !utils.IsValidUUID(tx.ID) {
		return errors.New("invalid ID: must be a valid UUID")
	}

	if !utils.IsTimestampWithinOneHour(tx.Timestamp) {
		return errors.New("invalid timestamp: must be recent within an hour")
	}

	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
		return errors.New("transaction must have inputs and outputs")
	}

	return nil
}

// Marshal serializes the Transaction
func (tx *Transaction) Marshal() ([]byte, error) {
	return cbor.Marshal(tx)
}

// Unmarshal deserializes the Transaction
func (tx *Transaction) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, tx)
}

type TransactionContext struct {
	Txn      *badger.Txn
	UTXOs    map[string][]UTXO
	Modified map[string]bool
	mu       sync.RWMutex
}

func NewTransactionContext(txn *badger.Txn) *TransactionContext {
	return &TransactionContext{
		Txn:      txn,
		UTXOs:    make(map[string][]UTXO),
		Modified: make(map[string]bool),
	}
}

// SerializeWithoutSignature prepares transaction for signing
func (tx *Transaction) SerializeWithoutSignature() ([]byte, error) {
	txCopy := *tx
	txCopy.Signature = nil
	return cbor.Marshal(txCopy)
}

// Basic signature verification
func (tx *Transaction) VerifySignature() error {
	txBytes, err := tx.SerializeWithoutSignature()
	if err != nil {
		return fmt.Errorf("failed to serialize transaction: %v", err)
	}

	if (tx.Salt == nil) || (len(tx.Salt) == 0) {
		return tx.Signature.Verify(&tx.SenderPublicKey, txBytes)
	}
	return tx.Signature.VerifyWithSalt(&tx.SenderPublicKey, txBytes, tx.Salt)
}

// Basic transaction structure validation
func (tx *Transaction) ValidateStructure() error {
	// Basic structure validation
	if len(tx.Salt) == 0 {
		return fmt.Errorf("transaction is missing salt")
	}
	if len(tx.Salt) != 32 {
		return fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
	}

	// Validate inputs and outputs exist
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
		return fmt.Errorf("transaction must have inputs and outputs")
	}

	// Validate amounts
	outputSum := amount.Amount(0)
	for _, output := range tx.Outputs {
		if output.Amount <= 0 {
			return fmt.Errorf("invalid output amount: %d", output.Amount)
		}
		outputSum += output.Amount
	}

	return nil
}
