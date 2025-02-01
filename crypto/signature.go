package crypto

type Signature interface {
	Bytes() []byte
	Verify(pubKey *PublicKey, data []byte) error
	VerifyWithSalt(pubKey *PublicKey, data, salt []byte) error
	String() string
	Marshal() ([]byte, error) //CBOR marshal
	Unmarshal([]byte) error   //CBOR unmarshal
	Equal(other Signature) bool
}
