package hash

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

const HashSize = 32

type Hash [HashSize]byte

func NewHash(data []byte) Hash {
	h := blake2b.Sum256(data)
	var hash Hash
	copy(hash[:], h[:HashSize])
	return hash
}

func FromString(str string) (Hash, error) {
	data, err := hex.DecodeString(str)
	if err != nil {
		return Hash{}, err
	}
	if len(data) != HashSize {
		return Hash{}, fmt.Errorf("Hash should be %d bytes, but it is %v bytes", HashSize, len(data))
	}
	return FromBytes(data)
}

func FromBytes(data []byte) (Hash, error) {
	if len(data) != HashSize {
		return Hash{}, fmt.Errorf("Hash should be %d bytes, but it is %v bytes", HashSize, len(data))
	}
	var h Hash
	copy(h[:], data[:HashSize])
	return h, nil
}

func (h *Hash) String() string {
	return hex.EncodeToString(h[:])
}

func (h *Hash) Bytes() []byte {
	return h[:]
}
