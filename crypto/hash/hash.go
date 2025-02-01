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

//TODO: optimise the hashing function
// // Initialize a cache with a mutex for concurrent access control
// var (
// 	addressCache = make(map[string]string)
// 	cacheMutex   sync.RWMutex
// )

// func CreateThrylosTransaction(id int) *thrylos.Transaction {
// 	return &thrylos.Transaction{
// 		Id:        fmt.Sprintf("tx%d", id),
// 		Inputs:    []*thrylos.UTXO{{TransactionId: "prev-tx-id", Index: 0, OwnerAddress: "Alice", Amount: 100}},
// 		Outputs:   []*thrylos.UTXO{{TransactionId: fmt.Sprintf("tx%d", id), Index: 0, OwnerAddress: "Bob", Amount: 100}},
// 		Timestamp: time.Now().Unix(),
// 		Signature: []byte("signature"), // This should be properly generated or mocked
// 		Sender:    "Alice",
// 	}
// }

// // Use a global hash pool for BLAKE2b hashers to reduce allocation overhead
// var blake2bHasherPool = sync.Pool{
// 	New: func() interface{} {
// 		hasher, err := blake2b.New256(nil)
// 		if err != nil {
// 			panic(err) // Proper error handling is essential, though panic should be avoided in production
// 		}
// 		return hasher
// 	},
// }

// func HashData(data []byte) []byte {
// 	hasher := blake2bHasherPool.Get().(hash.Hash)
// 	defer blake2bHasherPool.Put(hasher)
// 	hasher.Reset()
// 	hasher.Write(data)
// 	return hasher.Sum(nil) // Correct usage of Sum
// }
