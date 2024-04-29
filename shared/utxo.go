package shared

import (
	"encoding/json"
	"fmt"

	"github.com/thrylos-labs/thrylos/thrylos"

	flatbuffers "github.com/google/flatbuffers/go"
)

// UTXO represents an Unspent Transaction Output, which is the output of a blockchain transaction
// that has not been spent and can be used as an input in a new transaction. UTXOs are fundamental
// to understanding a user's balance within the blockchain.
type UTXO struct {
	ID            string `json:"ID,omitempty"` // Use omitempty if the field can be empty
	TransactionID string `json:"TransactionID"`
	Index         int    `json:"Index"`
	OwnerAddress  string `json:"OwnerAddress"`
	Amount        int    `json:"Amount"`
}

// This function will iterate over a slice of UTXO and create a new slice containing pointers to the elements of the original slice:
func ConvertToUTXOPtrs(utxos []UTXO) []*UTXO {
	utxoPtrs := make([]*UTXO, len(utxos))
	for i := range utxos {
		utxoPtrs[i] = &utxos[i]
	}
	return utxoPtrs
}

// ConvertSharedUTXOToProto converts a shared.UTXO to a protobuf UTXO message.
func ConvertSharedUTXOToFlatBuffers(builder *flatbuffers.Builder, u UTXO) flatbuffers.UOffsetT {
	// Create the strings in the builder.
	transactionID := builder.CreateString(u.TransactionID)
	ownerAddress := builder.CreateString(u.OwnerAddress)

	// Start the UTXO object.
	thrylos.UTXOStart(builder)

	// Add data to it.
	thrylos.UTXOAddTransactionId(builder, transactionID)
	thrylos.UTXOAddIndex(builder, int32(u.Index))
	thrylos.UTXOAddOwnerAddress(builder, ownerAddress)
	thrylos.UTXOAddAmount(builder, int64(u.Amount))

	// End the object and get the offset.
	return thrylos.UTXOEnd(builder)
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

// This utilizes the custom MarshalJSON method defined in the UTXO struct if present.
func SerializeUTXOs(builder *flatbuffers.Builder, utxos []*UTXO) (flatbuffers.UOffsetT, error) {
	if len(utxos) == 0 {
		return 0, fmt.Errorf("no UTXOs provided")
	}

	offsets := make([]flatbuffers.UOffsetT, len(utxos))
	for i, utxo := range utxos {
		if utxo == nil {
			return 0, fmt.Errorf("nil UTXO found at index %d", i)
		}
		transactionID := builder.CreateString(utxo.TransactionID)
		ownerAddress := builder.CreateString(utxo.OwnerAddress)
		thrylos.UTXOStart(builder)
		thrylos.UTXOAddTransactionId(builder, transactionID)
		thrylos.UTXOAddIndex(builder, int32(utxo.Index)) // Convert Index to int32
		thrylos.UTXOAddOwnerAddress(builder, ownerAddress)
		thrylos.UTXOAddAmount(builder, int64(utxo.Amount)) // Convert Amount to int64
		offsets[i] = thrylos.UTXOEnd(builder)
	}
	thrylos.TransactionStartInputsVector(builder, len(offsets))
	for i := len(offsets) - 1; i >= 0; i-- {
		builder.PrependUOffsetT(offsets[i])
	}
	return builder.EndVector(len(offsets)), nil
}

// MarkUTXOAsSpent removes a UTXO from the set of available UTXOs, effectively marking it as spent.
// This operation is critical in preventing double-spending within the blockchain system.
func MarkUTXOAsSpent(utxoID string, allUTXOs map[string]UTXO) {
	delete(allUTXOs, utxoID)
}
