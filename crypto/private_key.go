package crypto

type PrivateKey interface {
	Bytes() []byte
	String() string
	Sign(msg []byte) *Signature
	PublicKey() *PublicKey
	Equal(other *PrivateKey) bool
}
