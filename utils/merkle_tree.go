package utils

import (
	"errors"
	"fmt"
	// "fmt" // Only needed if adding logging
	"golang.org/x/crypto/blake2b" // Import blake2b
)

// ComputeMerkleRoot calculates the Merkle root for a list of byte slices using BLAKE2b-256.
// It handles cases with 0 or 1 data items and pads levels with odd numbers of nodes.
func ComputeMerkleRoot(data [][]byte) ([]byte, error) {
	if len(data) == 0 {
		// Return nil or a specific "empty" hash if preferred
		return nil, nil // Indicates no root for empty data set
	}

	// Initialize BLAKE2b hasher (can reuse one instance)
	// Using New256 ensures a 32-byte output, matching your HashSize
	hasher, err := blake2b.New256(nil)
	if err != nil {
		// Handle error during hasher creation (should not happen with nil key)
		return nil, fmt.Errorf("failed to create blake2b hasher: %w", err)
	}

	// Start with the initial hashes of the data items
	var level [][]byte
	for _, item := range data {
		if item == nil {
			return nil, errors.New("cannot compute Merkle root with nil data item")
		}
		// Hash the item using BLAKE2b
		hasher.Reset() // Reset hasher for new input
		hasher.Write(item)
		level = append(level, hasher.Sum(nil)) // Get the hash result
	}

	// Iteratively compute parent levels until only the root remains
	for len(level) > 1 {
		// If the level has an odd number of nodes, duplicate the last one
		if len(level)%2 != 0 {
			level = append(level, level[len(level)-1])
		}

		var nextLevel [][]byte
		// Process pairs of nodes
		for i := 0; i < len(level); i += 2 {
			node1 := level[i]
			node2 := level[i+1]

			// Concatenate the pair of hashes
			combined := append(node1, node2...)

			// Hash the combined pair to get the parent node hash using BLAKE2b
			hasher.Reset()
			hasher.Write(combined)
			nextLevel = append(nextLevel, hasher.Sum(nil))
		}
		level = nextLevel // Move to the next level up
	}

	// The single remaining hash is the Merkle root
	if len(level) == 1 {
		return level[0], nil
	}

	// This case should ideally not be reached if data was not empty
	return nil, errors.New("merkle tree construction failed unexpectedly")
}
