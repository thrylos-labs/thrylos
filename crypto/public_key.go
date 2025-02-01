package crypto

import "github.com/thrylos-labs/thrylos/crypto/address"

type PublicKey interface {
	Bytes() []byte
	String() string
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
	Verify(data []byte, signature *Signature) error
	Address() (*address.Address, error)
	Compare(other *PublicKey) bool
}
