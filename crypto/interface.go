package crypto

import "github.com/thrylos-labs/thrylos/crypto/address"

type PrivateKey interface {
	Bytes() []byte
	String() string
	Sign(msg []byte) Signature
	PublicKey() PublicKey
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
	Equal(other *PrivateKey) bool
}

type PublicKey interface {
	Bytes() []byte
	Address() (*address.Address, error)
	String() string
	Verify(data []byte, signature *Signature) error
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
	Equal(other *PublicKey) bool
}

type Signature interface {
	Bytes() []byte
	Verify(pubKey *PublicKey, data []byte) error
	VerifyWithSalt(pubKey *PublicKey, data, salt []byte) error
	String() string
	Marshal() ([]byte, error) //CBOR marshal
	Unmarshal([]byte) error   //CBOR unmarshal
	Equal(other Signature) bool
}
