package utils

import (
	"crypto/sha256"
	"errors"
	// Import fmt if needed for errors below
	// If you add logging inside ComputeMerkleRoot
)

// ComputeMerkleRoot calculates the Merkle root for a list of byte slices (hashes or serialized data).
// It handles cases with 0 or 1 data items and pads levels with odd numbers of nodes.
func ComputeMerkleRoot(data [][]byte) ([]byte, error) {
	if len(data) == 0 {
		// Return nil or a specific "empty" hash if preferred
		return nil, nil // Indicates no root for empty data set
	}

	// Start with the initial hashes of the data items
	var level [][]byte
	for _, item := range data {
		if item == nil {
			// Decide how to handle nil data - skip, error, or use a placeholder hash?
			// Returning an error is safest.
			return nil, errors.New("cannot compute Merkle root with nil data item")
		}
		// We assume 'item' is the data to be hashed (e.g., marshalled tx)
		// If 'item' was already a hash, you would skip this hashing step.
		hasher := sha256.New()
		hasher.Write(item)
		level = append(level, hasher.Sum(nil))
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

			// Hash the combined pair to get the parent node hash
			hasher := sha256.New()
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
