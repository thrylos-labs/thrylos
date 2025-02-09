package chain

import (
	"errors"

	"github.com/gballet/go-verkle"
)

// Acts as an organized way to store and verify transaction data

const (
	KeySize       = 32 // Standard key size for Verkle trees
	LeafValueSize = 32 // Define LeafValueSize if it's standard for leaf values in Verkle trees
)

func NewVerkleTree(data [][]byte) (verkle.VerkleNode, error) {
	if len(data) == 0 {
		return nil, errors.New("no data provided for Verkle tree creation")
	}

	root := verkle.New() // Initialize the Verkle tree

	for _, item := range data {
		if len(item) < KeySize+LeafValueSize {
			return nil, errors.New("data item is too short to contain a valid key and value")
		}
		key := item[:KeySize]
		value := item[KeySize : KeySize+LeafValueSize] // Correctly segment the value based on LeafValueSize

		if err := root.Insert(key, value, nil); err != nil {
			return nil, err
		}
	}

	return root, nil
}
