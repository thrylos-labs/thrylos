package crypto

type Signature interface {
	Bytes() []byte
	String() string
	Marshal() ([]byte, error) //CBOR marshal
	Unmarshal([]byte) error   //CBOR unmarshal
	Compare(other Signature) bool
}
