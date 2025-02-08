package shared

import (
	"encoding/base64"

	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/hash"
)

// Package shared contains the Block type definition and basic methods.

// Block represents a single unit of data within the blockchain
type Block struct {
	Index              int64            `cbor:"1,keyasint"`
	Timestamp          int64            `cbor:"2,keyasint"`
	VerkleRoot         []byte           `cbor:"3,keyasint"`
	PrevHash           hash.Hash        `cbor:"4,keyasint"`
	Hash               hash.Hash        `cbor:"5,keyasint,omitempty"`
	Transactions       []*Transaction   `cbor:"6,keyasint"`
	Data               string           `cbor:"7,keyasint,omitempty"`
	ValidatorPublicKey crypto.PublicKey `cbor:"8,keyasint"`
	Signature          crypto.Signature `cbor:"9,keyasint,omitempty"`
	Salt               []byte           `cbor:"10,keyasint"`
	Validator          string           `cbor:"11,keyasint"`
}

// Basic methods that don't require chain-specific logic
func (b *Block) Marshal() ([]byte, error) {
	return cbor.Marshal(b)
}

func (b *Block) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, b)
}

func (b *Block) GetVerkleRootBase64() string {
	return base64.StdEncoding.EncodeToString(b.VerkleRoot)
}
