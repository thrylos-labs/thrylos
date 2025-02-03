package shared

import (
	"sync"

	"github.com/thrylos-labs/thrylos/amount"
	"github.com/thrylos-labs/thrylos/crypto"
	"github.com/thrylos-labs/thrylos/crypto/mldsa44"
)

type Validator struct {
	PublicKey crypto.PublicKey `cbor:"1,keyasint"`
	Number    int32            `cbor:"2,keyasint"`
	Stake     amount.Amount    `cbor:"3,keyasint"`
}

type ValidatorKeyStore struct {
	keys map[string]*mldsa44.PrivateKey
	mu   sync.RWMutex
}
