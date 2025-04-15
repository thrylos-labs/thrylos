package chaintests

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/address"
	"github.com/thrylos-labs/thrylos/types"
)

// MockPublicKey implements the crypto.PublicKey interface
type MockPublicKey struct {
	Key     string
	address *address.Address
}

func NewMockPublicKey(key string) crypto.PublicKey {
	addr := NewMockAddress("mock-" + key + "-address")
	return &MockPublicKey{
		Key:     key,
		address: addr,
	}
}

func (mpk *MockPublicKey) Marshal() ([]byte, error) {
	return cbor.Marshal(mpk)
}

func (mpk *MockPublicKey) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, mpk)
}

func (mpk *MockPublicKey) Bytes() []byte {
	return []byte(mpk.Key)
}

func (mpk *MockPublicKey) String() string {
	return mpk.Key
}

func (mpk *MockPublicKey) Equal(other *crypto.PublicKey) bool {
	if other == nil {
		return false
	}
	return mpk.String() == (*other).String()
}

func (mpk *MockPublicKey) Address() (*address.Address, error) {
	return mpk.address, nil
}

func (mpk *MockPublicKey) Verify(data []byte, signature *crypto.Signature) error {
	return nil // Always succeed for testing
}

// MockSignature implements the crypto.Signature interface
type MockSignature struct {
	sig []byte
}

// Marshal implements crypto.Signature.
func (ms *MockSignature) Marshal() ([]byte, error) {
	return cbor.Marshal(ms.sig)
}

func (ms *MockSignature) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, &ms.sig)
}

func NewMockSignature(sig string) crypto.Signature {
	return &MockSignature{
		sig: []byte(sig),
	}
}

// MockSignature type assertion methods
func (ms *MockSignature) MarshalJSON() ([]byte, error) {
	if ms == nil || len(ms.sig) == 0 {
		return []byte("null"), nil
	}
	return []byte(fmt.Sprintf("%q", base64.StdEncoding.EncodeToString(ms.sig))), nil
}

func (ms *MockSignature) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		if string(data) == "null" {
			ms.sig = nil
			return nil
		}
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	ms.sig = decoded
	return nil
}

func (ms *MockSignature) Bytes() []byte                                      { return ms.sig }
func (ms *MockSignature) String() string                                     { return string(ms.sig) }
func (ms *MockSignature) Verify(pubKey *crypto.PublicKey, data []byte) error { return nil }
func (ms *MockSignature) VerifyWithSalt(pubKey *crypto.PublicKey, data, salt []byte) error {
	return nil
}
func (ms *MockSignature) Equal(other crypto.Signature) bool {
	return bytes.Equal(ms.Bytes(), other.Bytes())
}

// MockTransactionJSON is a helper struct for JSON marshaling/unmarshaling
type MockTransactionJSON struct {
	ID               string       `json:"id"`
	Timestamp        int64        `json:"timestamp"`
	Inputs           []types.UTXO `json:"inputs"`
	Outputs          []types.UTXO `json:"outputs"`
	EncryptedInputs  []byte       `json:"encryptedInputs,omitempty"`
	EncryptedOutputs []byte       `json:"encryptedOutputs,omitempty"`
	EncryptedAESKey  []byte       `json:"encryptedAESKey"`
	PreviousTxIds    []string     `json:"previousTxIds"`
	SenderAddress    string       `json:"senderAddress"`
	SenderPublicKey  string       `json:"senderPublicKey"`
	Signature        string       `json:"signature,omitempty"`
	GasFee           int          `json:"gasFee"`
	BlockHash        string       `json:"blockHash,omitempty"`
	Salt             []byte       `json:"salt,omitempty"`
	Status           string       `json:"status,omitempty"`
}

// CreateMockTransaction now uses CBOR encoding
// Updated CreateMockTransaction with correct amount balance
func CreateMockTransaction() ([]byte, error) {
	addr := NewMockAddress("sender123")
	pubKey := NewMockPublicKey("mockPublicKey123")
	sig := NewMockSignature("mockSignature123")

	// Calculate amounts to satisfy: input = output + gas fee
	const (
		gasFee       = 1000
		outputAmount = 50
		inputAmount  = outputAmount + gasFee // 1050
	)

	jsonTx := &MockTransactionJSON{
		ID:        "tx123",
		Timestamp: 1609459200,
		Inputs: []types.UTXO{
			{
				TransactionID: "tx100",
				Index:         0,
				Amount:        inputAmount, // Now 1050 instead of 50
			},
		},
		Outputs: []types.UTXO{
			{
				TransactionID: "tx123",
				Index:         0,
				OwnerAddress:  "recipientAddress",
				Amount:        outputAmount, // Stays 50
			},
		},
		SenderAddress:   base64.StdEncoding.EncodeToString(addr.Bytes()),
		SenderPublicKey: base64.StdEncoding.EncodeToString([]byte(pubKey.(*MockPublicKey).Key)),
		Signature:       base64.StdEncoding.EncodeToString(sig.Bytes()),
		GasFee:          gasFee,
		EncryptedAESKey: []byte("mock-aes-key"),
		PreviousTxIds:   []string{"tx100"},
		Status:          "pending",
	}

	return json.Marshal(jsonTx)
}

// MockAddress matches the actual Address type structure
type MockAddress [address.AddressWords]byte // <<< Use AddressWords

// NewMockAddress creates a new mock address from a string
func NewMockAddress(addr string) *address.Address {
	var mockAddr address.Address
	hash := sha256.Sum256([]byte(addr))
	copy(mockAddr[:], hash[:address.AddressWords]) // <<< Use AddressWords
	return &mockAddr
}

// Ensure these interfaces are properly implemented
var (
	_ crypto.PublicKey = (*MockPublicKey)(nil)
	_ crypto.Signature = (*MockSignature)(nil)
)

// MarshalJSON implements json.Marshaler
func (mpk *MockPublicKey) MarshalJSON() ([]byte, error) {
	if mpk == nil {
		return []byte("null"), nil
	}
	return []byte(fmt.Sprintf("%q", base64.StdEncoding.EncodeToString([]byte(mpk.Key)))), nil
}

func (mpk *MockPublicKey) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	mpk.Key = string(decoded)
	mpk.address = NewMockAddress(string(decoded))
	return nil
}
