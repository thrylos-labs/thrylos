package types

import (
	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
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

// TransactionContext interface defines the methods that must be implemented
type TransactionContext interface {
	GetUTXOs() map[string][]UTXO
	SetUTXOs(utxos map[string][]UTXO)
	IsModified(key string) bool
	SetModified(key string)
	GetTransaction() *Transaction
	Commit() error
	Rollback() error
}

// Marshal serializes the transaction into CBOR format
func (tx *Transaction) Marshal() ([]byte, error) {
	return cbor.Marshal(tx)
}

// Unmarshal deserializes the transaction from CBOR format
func (tx *Transaction) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, tx)
}
