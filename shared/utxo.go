package shared

import (
	thrylos "Thrylos"
	"encoding/json"
	"fmt"
)

// UTXO represents an Unspent Transaction Output, which is the output of a blockchain transaction
// that has not been spent and can be used as an input in a new transaction. UTXOs are fundamental
// to understanding a user's balance within the blockchain.
type UTXO struct {
	ID            string // Unique identifier for the UTXO, often a hash.
	TransactionID string // Identifier of the transaction that created this UTXO.
	Index         int    // Position of this output in the transaction's list of outputs.
	OwnerAddress  string // Blockchain address of the owner who can spend this UTXO.
	Amount        int    // Amount of digital currency this UTXO represents.
}

// When creating or updating transactions to be serialized with Protobuf, you'll use ConvertSharedUTXOToProto to convert your application's internal UTXO representations into the format expected by Protobuf before serialization.

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
func CreateUTXO(id, txID string, index int, owner string, amount int) UTXO {
	fmt.Printf("Creating UTXO with ID: %s, TransactionID: %s, Index: %d, Owner: %s, Amount: %d\n", id, txID, index, owner, amount)
	return UTXO{
		ID:            id,
		TransactionID: txID, // Ensure this is the ID of the transaction creating this UTXO
		Index:         index,
		OwnerAddress:  owner,
		Amount:        amount,
	}
}

// MarkUTXOAsSpent removes a UTXO from the set of available UTXOs, effectively marking it as spent.
// This operation is critical in preventing double-spending within the blockchain system.
func MarkUTXOAsSpent(utxoID string, allUTXOs map[string]UTXO) {
	delete(allUTXOs, utxoID)
}
