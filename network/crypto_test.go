package network // Or your actual package name

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	// --- CHANGE IMPORT ---
	// Use mldsa44 instead of mldsa65
	// Ensure this is the correct path to the CIRCL mldsa44 implementation
	mldsa44 "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	// --- END CHANGE ---
)

// Renamed to reflect the level being tested
func TestSigningAndVerificationDirect_MLDSA44(t *testing.T) {
	t.Log("Starting Direct CIRCL Sign/Verify Test using ML-DSA-44 and GenerateKey") // Updated log

	// 1. Generate keys DIRECTLY using CIRCL ML-DSA-44
	// --- CHANGE FUNCTION CALL ---
	circlPubKey, circlPrivKey, err := mldsa44.GenerateKey(rand.Reader) // Use mldsa44 GenerateKey
	if err != nil {
		t.Fatalf("mldsa44.GenerateKey failed: %v", err) // Updated error message
	}
	if circlPubKey == nil || circlPrivKey == nil {
		t.Fatalf("mldsa44.GenerateKey returned nil key(s)") // Updated error message
	}
	// --- Type references will implicitly use mldsa44 types now ---
	t.Logf("Generated keys directly (PK Type: %T, SK Type: %T)", circlPubKey, circlPrivKey)

	// 2. Define message (can keep the same simple message)
	msg := []byte("test message for direct verification")
	t.Logf("Message: %q", msg)

	// 3. Sign DIRECTLY using CIRCL ML-DSA-44
	// --- CHANGE CONSTANT & FUNCTION CALL ---
	signatureBytes := make([]byte, mldsa44.SignatureSize)                       // Use mldsa44 size
	ctx := []byte(nil)                                                          // Explicitly nil context
	useRandomized := false                                                      // Non-randomized signing
	err = mldsa44.SignTo(circlPrivKey, msg, ctx, useRandomized, signatureBytes) // Use mldsa44 SignTo
	if err != nil {
		t.Fatalf("mldsa44.SignTo failed: %v", err) // Updated error message
	}
	// Log signature details (using helper function for brevity)
	logSigLen := min(len(signatureBytes), 16)
	t.Logf("Signed directly using mldsa44. Signature len: %d, Sig bytes (hex, first %d): %s", len(signatureBytes), logSigLen, hex.EncodeToString(signatureBytes[:logSigLen])) // Updated log

	// 4. Verify DIRECTLY using CIRCL ML-DSA-44
	// --- CHANGE FUNCTION CALL & ARG ORDER ---
	// Verify signature: Verify(pk *PublicKey, msg, ctx, sig []byte) bool
	isValid := mldsa44.Verify(circlPubKey, msg, ctx, signatureBytes)    // Use mldsa44 Verify with nil context (ctx)
	t.Logf(">>> Direct ML-DSA-44 Verification Result: %v <<<", isValid) // Updated log

	// 5. Check result
	if !isValid {
		t.Errorf("Direct CIRCL ML-DSA-44 signature verification FAILED!") // Updated error message
	} else {
		t.Logf("Direct CIRCL ML-DSA-44 signature verification SUCCEEDED!") // Updated log
	}
}

// Helper function (keep as is - useful for logging)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
