package crypto

type PublicKey interface {
	Bytes() []byte
	String() string
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
	Verify(data []byte, signature Signature) error
	Address() *Address
	Compare(other PublicKey) bool
}
