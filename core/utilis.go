package core

import (
	"crypto/rand"
	"math/big"
)

// SecureRandomInt generates a cryptographically secure random integer within the range [0, max).
// It uses the crypto/rand package to ensure the randomness is suitable for security-sensitive operations.
// This function can be used in various blockchain contexts where randomness is required, such as
// selecting a validator randomly in a Proof of Stake (PoS) consensus mechanism or generating nonces.
//
// Parameters:
// - max: The upper limit for the random number generation. The generated number will be in the range [0, max).
//
// Returns:
// - int: A random integer in the specified range.
// - error: An error object if the random number generation fails.
func SecureRandomInt(max int) (int, error) {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(nBig.Int64()), nil
}
