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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto/hash"
	"github.com/thrylos-labs/thrylos/types"
)

// TransactionContextImpl implements the types.TransactionContext interface
type TransactionContextImpl struct {
	txn         *badger.Txn
	utxos       map[string][]types.UTXO
	modified    map[string]bool
	mu          sync.RWMutex
	transaction *types.Transaction
}

type TransactionForSigning struct {
	ID               string       `json:"id"`
	Timestamp        int64        `json:"timestamp"`
	Inputs           []types.UTXO `json:"inputs"`
	Outputs          []types.UTXO `json:"outputs"`
	EncryptedInputs  []byte       `json:"encryptedInputs,omitempty"`
	EncryptedOutputs []byte       `json:"encryptedOutputs,omitempty"`
	EncryptedAESKey  []byte       `json:"encryptedAESKey,omitempty"`
	PreviousTxIds    []string     `json:"previousTxIds,omitempty"`
	Sender           string       `json:"sender"`
	GasFee           int          `json:"gasFee"`
}

// Implement the TransactionContext interface
func (tc *TransactionContextImpl) GetUTXOs() map[string][]types.UTXO {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.utxos
}

func (tc *TransactionContextImpl) SetUTXOs(utxos map[string][]types.UTXO) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.utxos = utxos
}

func (tc *TransactionContextImpl) IsModified(key string) bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.modified[key]
}

func (tc *TransactionContextImpl) SetModified(key string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.modified[key] = true
}

func (tc *TransactionContextImpl) Commit() error {
	return tc.txn.Commit()
}

func (tc *TransactionContextImpl) Rollback() error {
	tc.txn.Discard() // In badger v3, we use Discard() instead of Rollback()
	return nil
}

// Constructor
func NewTransactionContext(txn *badger.Txn) types.TransactionContext {
	return &TransactionContextImpl{
		txn:         txn,
		utxos:       make(map[string][]types.UTXO),
		modified:    make(map[string]bool),
		transaction: nil,
	}
}

func (tc *TransactionContextImpl) GetBadgerTxn() *badger.Txn {
	return tc.txn
}

func (tc *TransactionContextImpl) GetTransaction() *types.Transaction {
	// Implementation here
	return nil // Or return actual transaction if you have it
}

// Transaction creation and validation functions
func NewTransaction(id string, inputs, outputs []types.UTXO) *types.Transaction {
	return &types.Transaction{
		ID:        id,
		Inputs:    inputs,
		Outputs:   outputs,
		Timestamp: time.Now().Unix(),
	}
}

// ValidateTransactionStructure performs structural validation of the transaction
func ValidateTransactionStructure(tx *types.Transaction) error {
	if len(tx.Salt) == 0 {
		return fmt.Errorf("transaction is missing salt")
	}
	if len(tx.Salt) != 32 {
		return fmt.Errorf("invalid salt length: expected 32 bytes, got %d", len(tx.Salt))
	}

	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
		return fmt.Errorf("transaction must have inputs and outputs")
	}

	outputSum := amount.Amount(0)
	for _, output := range tx.Outputs {
		if output.Amount <= 0 {
			return fmt.Errorf("invalid output amount: %d", output.Amount)
		}
		outputSum += output.Amount
	}

	return nil
}

// Transaction serialization functions
func SerializeTransaction(tx *types.Transaction) ([]byte, error) {
	return cbor.Marshal(tx)
}

func UnserializeTransaction(data []byte) (*types.Transaction, error) {
	var tx types.Transaction
	err := cbor.Unmarshal(data, &tx)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

func SerializeTransactionWithoutSignature(tx *types.Transaction) ([]byte, error) {
	txCopy := *tx
	txCopy.Signature = nil
	return cbor.Marshal(txCopy)
}

// VerifyTransactionSignature verifies the transaction signature
func VerifyTransactionSignature(tx *types.Transaction) error {
	txBytes, err := SerializeTransactionWithoutSignature(tx)
	if err != nil {
		return fmt.Errorf("failed to serialize transaction: %v", err)
	}

	if (tx.Salt == nil) || (len(tx.Salt) == 0) {
		return tx.Signature.Verify(&tx.SenderPublicKey, txBytes)
	}
	return tx.Signature.VerifyWithSalt(&tx.SenderPublicKey, txBytes, tx.Salt)
}

func ValidateTransaction(tx *types.Transaction, availableUTXOs map[string][]types.UTXO) error {
	// First perform structure validation using shared validation function
	if err := ValidateTransactionStructure(tx); err != nil {
		return fmt.Errorf("structure validation failed: %w", err)
	}

	// Blockchain-specific validation
	inputSum := amount.Amount(0)
	for _, input := range tx.Inputs {
		// Construct the key used to find the UTXOs for this input
		utxoKey := fmt.Sprintf("%s-%d", input.TransactionID, input.Index) // Use string formatting instead of Key() method

		utxos, exists := availableUTXOs[utxoKey]
		if !exists || len(utxos) == 0 {
			return fmt.Errorf("input UTXO not found or empty slice: %s", utxoKey)
		}

		// Verify UTXO ownership and amount
		if utxos[0].OwnerAddress != tx.SenderAddress.String() {
			return fmt.Errorf("UTXO owner mismatch for: %s", utxoKey)
		}

		inputSum += utxos[0].Amount
	}

	// Calculate output sum
	outputSum := amount.Amount(0)
	for _, output := range tx.Outputs {
		outputSum += output.Amount
	}

	// Validate balance including gas fee
	if inputSum != outputSum+amount.Amount(tx.GasFee) {
		return fmt.Errorf("input sum (%d) does not match output sum (%d) plus gas fee (%d)",
			inputSum, outputSum, tx.GasFee)
	}
	return nil
}

func SerializeTransactionForSigning(tx *types.Transaction) ([]byte, error) {
	txForSigning := TransactionForSigning{
		ID:               tx.ID,
		Timestamp:        tx.Timestamp,
		Inputs:           tx.Inputs,
		Outputs:          tx.Outputs,
		EncryptedInputs:  tx.EncryptedInputs,
		EncryptedOutputs: tx.EncryptedOutputs,
		EncryptedAESKey:  tx.EncryptedAESKey,
		PreviousTxIds:    tx.PreviousTxIds,
		Sender:           tx.SenderAddress.String(),
		GasFee:           tx.GasFee,
	}
	return json.Marshal(txForSigning)
}

// SanitizeAndFormatAddress cleans and validates blockchain addresses.
func SanitizeAndFormatAddress(address string) (string, error) {
	// Trim any leading/trailing whitespace
	address = strings.TrimSpace(address)

	// Check if the address starts with the correct prefix
	if !strings.HasPrefix(address, "tl1") {
		return "", fmt.Errorf("invalid address: must start with 'tl1'")
	}

	// Attempt to decode the Bech32 address
	_, decoded, err := bech32.Decode(address)
	if err != nil {
		return "", fmt.Errorf("invalid Bech32 address: %v", err)
	}

	// Re-encode to ensure it's in the canonical format
	reencoded, err := bech32.Encode("tl1", decoded)
	if err != nil {
		return "", fmt.Errorf("failed to re-encode address: %v", err)
	}

	return reencoded, nil
}

// GenerateTransactionID creates a unique identifier for a transaction based on its contents.
func GenerateTransactionID(inputs []types.UTXO, outputs []types.UTXO, address string, amount, gasFee int) (string, error) {
	var builder strings.Builder

	// Append the sender's address
	builder.WriteString(address)

	// Append the amount and gas fee
	builder.WriteString(fmt.Sprintf("%d%d", amount, gasFee))

	// Append details of inputs and outputs
	for _, input := range inputs {
		builder.WriteString(fmt.Sprintf("%s%d", input.OwnerAddress, input.Amount))
	}
	for _, output := range outputs {
		builder.WriteString(fmt.Sprintf("%s%d", output.OwnerAddress, output.Amount))
	}

	// Use the HashData function from the hash package
	hashBytes := hash.HashData([]byte(builder.String()))
	return hex.EncodeToString(hashBytes), nil
}

// Additional helper functions for converting between types
func UTXOToMap(utxo *types.UTXO) map[string]interface{} {
	return map[string]interface{}{
		"TransactionID": utxo.TransactionID,
		"Index":         utxo.Index,
		"OwnerAddress":  utxo.OwnerAddress,
		"Amount":        utxo.Amount,
		"IsSpent":       utxo.IsSpent,
	}
}

func UTXOsToMapSlice(utxos []*types.UTXO) []map[string]interface{} {
	result := make([]map[string]interface{}, len(utxos))
	for i, utxo := range utxos {
		result[i] = UTXOToMap(utxo)
	}
	return result
}

func ValidateTransactionBalance(tx *types.Transaction) error {
	if tx.SenderAddress.String() == "" { // Changed Sender to SenderAddress
		return fmt.Errorf("transaction sender address is empty")
	}

	if len(tx.Inputs) == 0 {
		return fmt.Errorf("transaction has no inputs")
	}
	if len(tx.Outputs) == 0 {
		return fmt.Errorf("transaction has no outputs")
	}

	// Validate that all inputs belong to sender
	senderAddr := tx.SenderAddress.String() // Get string representation once
	for _, input := range tx.Inputs {
		if input.OwnerAddress != senderAddr {
			return fmt.Errorf("input address %s does not match sender %s",
				input.OwnerAddress, senderAddr)
		}
	}

	var inputSum, outputSum amount.Amount // Changed to amount.Amount type

	// Validate inputs (in nanoTHRYLOS)
	for _, input := range tx.Inputs {
		if input.Amount <= 0 {
			return fmt.Errorf("invalid input amount: %d nanoTHRYLOS", input.Amount)
		}
		inputSum += input.Amount
	}

	// Validate outputs (in nanoTHRYLOS)
	for _, output := range tx.Outputs {
		if output.Amount <= 0 {
			return fmt.Errorf("invalid output amount: %d nanoTHRYLOS", output.Amount)
		}
		outputSum += output.Amount
	}

	// Convert gas fee to amount.Amount to ensure type consistency
	gasFeeAmount := amount.Amount(tx.GasFee)

	log.Printf("Transaction validation - Input sum: %s", inputSum)
	log.Printf("Transaction validation - Output sum: %s", outputSum)
	log.Printf("Transaction validation - Gas fee: %s", gasFeeAmount)
	log.Printf("Transaction validation - Total (outputs + gas fee): %s", outputSum+gasFeeAmount)

	// Account for gas fee in the balance calculation using amount.Amount arithmetic
	if inputSum != outputSum+gasFeeAmount {
		return fmt.Errorf("inputs (%s) do not match outputs (%s) plus gas fee (%s)",
			inputSum, outputSum, gasFeeAmount)
	}

	return nil
}
