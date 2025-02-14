// types/utxo.go
package types

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto/address"
)

// UTXO represents an Unspent Transaction Output
type UTXO struct {
	ID            string        `cbor:"1,keyasint,omitempty"`
	Index         int           `cbor:"2,keyasint"`
	TransactionID string        `cbor:"3,keyasint"`
	OwnerAddress  string        `cbor:"4,keyasint"`
	Amount        amount.Amount `cbor:"5,keyasint"`
	IsSpent       bool          `cbor:"6,keyasint"`
}

// UTXO methods stay with the type
func (u *UTXO) Validate() error {
	if !address.Validate(u.OwnerAddress) {
		return fmt.Errorf("invalid owner address format: %s", u.OwnerAddress)
	}
	return nil
}

func (u *UTXO) Key() string {
	return fmt.Sprintf("%s-%d", u.TransactionID, u.Index)
}

func (u *UTXO) Marshal() ([]byte, error) {
	return cbor.Marshal(u)
}

func (u *UTXO) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, u)
}
