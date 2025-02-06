package shared

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

// UTXO is placed in the shared package because:
// 1. It's a core data structure used by multiple packages (balance, chain, node)
// 2. Having it here prevents circular dependencies between packages
// 3. It contains only the basic UTXO structure and methods, not specific chain logic

// UTXO represents an Unspent Transaction Output, which is the output of a blockchain transaction
// that has not been spent and can be used as an input in a new transaction. UTXOs are fundamental
// to understanding a user's balance within the blockchain.
type UTXO struct {
	ID            string        `cbor:"1,keyasint,omitempty"`
	Index         int           `cbor:"2,keyasint"`
	TransactionID string        `cbor:"3,keyasint"` // Changed from transactionid
	OwnerAddress  string        `cbor:"4,keyasint"` // Already correct
	Amount        amount.Amount `cbor:"5,keyasint"`
	IsSpent       bool          `cbor:"6,keyasint"` // Changed from isspent
}

// CreateUTXO creates a new UTXO instance with the given parameters.
// CreateUTXO initializes a new UTXO with the specified attributes. This function is typically
// called when a transaction is processed, and its outputs are being determined.
func CreateUTXO(id string, index int, txID string, owner string, coinAmount float64, isSpent bool) *UTXO {
	fmt.Printf("Creating UTXO with ID: %s, TransactionID: %s, Index: %d, Owner: %s, Amount: %f\n", id, txID, index, owner, coinAmount)

	formatedAmount, err := amount.NewAmount(coinAmount)
	if err != nil {
		fmt.Printf("Error creating UTXO: %v\n", err)
		return nil
	}
	return &UTXO{
		ID:            id,
		Index:         index,
		TransactionID: txID,
		OwnerAddress:  owner,
		Amount:        formatedAmount,
		IsSpent:       isSpent,
	}
}

// ValidateUTXO checks for the validity of the UTXO, ensuring its data conforms to expected formats and rules.
func (u *UTXO) Validate() error {
	// Check if the owner address is correctly formatted
	if !address.Validate(u.OwnerAddress) {
		return fmt.Errorf("invalid owner address format: %s", u.OwnerAddress)
	}
	// Further validation rules can be added here
	return nil
}
func (u *UTXO) Key() string {
	key := fmt.Sprintf("%s-%d", u.TransactionID, u.Index)
	return key
}

// Marshal serializes the UTXO struct into CBOR format.
func (u *UTXO) Marshal() ([]byte, error) {
	return cbor.Marshal(u)
}

// Unmarshal deserializes the CBOR data into a UTXO struct.
func (u *UTXO) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, u)
}

// MarkUTXOAsSpent removes a UTXO from the set of available UTXOs, effectively marking it as spent.
// This operation is critical in preventing double-spending within the blockchain system.
func MarkUTXOAsSpent(utxoID string, allUTXOs map[string]UTXO) {
	delete(allUTXOs, utxoID)
}
