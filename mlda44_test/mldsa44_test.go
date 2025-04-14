package mldsa44_test // Or your relevant test package name

import (
	// To potentially compare keys/signatures if needed later
	"crypto/rand" // For key generation
	"testing"     // Go testing framework

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	// --- IMPORTANT: Ensure this import path is correct for your mldsa44 package ---
	// Make sure the path points to where your mldsa44 code actually is.
	// The previous run used github.com/thrylos-labs/thrylos/mlda44_test
	// which implies the package might be github.com/thrylos-labs/thrylos/mlda44 ?
)

// TestMLDSA44SignVerify tests the basic ML-DSA-44 sign and verify workflow,
// including context handling and failure cases.
func TestMLDSA44SignVerify(t *testing.T) {
	t.Log("Starting ML-DSA-44 Sign/Verify Test")

	// 1. Generate Key Pair
	pk, sk, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ML-DSA-44 keys: %v", err)
	}
	if pk == nil || sk == nil {
		t.Fatal("Generated key pair contains nil values")
	}
	t.Logf("Generated keys (PK Type: %T, SK Type: %T)", pk, sk)

	// 2. Define Message and Context
	message := []byte("This is the test message for ML-DSA-44.")
	var ctx []byte = nil // Start with nil context
	t.Logf("Message to sign: %q", string(message))
	t.Logf("Context (ctx): %v", ctx)

	// 3. Sign the Message (using nil context)
	sig := make([]byte, mldsa44.SignatureSize)
	useRandomized := false
	err = mldsa44.SignTo(sk, message, ctx, useRandomized, sig)
	if err != nil {
		t.Fatalf("Failed to sign message using SignTo (nil context): %v", err)
	}
	t.Logf("Signed message (nil context). Signature length: %d (Expected: %d)", len(sig), mldsa44.SignatureSize)
	if len(sig) >= 16 {
		t.Logf("Signature bytes (hex, first 16): %x", sig[:16])
	} else {
		t.Logf("Signature bytes (hex): %x", sig)
	}

	// 4. Verify the Signature (using nil context)
	isValid := mldsa44.Verify(pk, message, ctx, sig)
	t.Logf("Verification result (nil context): %t", isValid)

	// 5. Assert the result (nil context)
	if !isValid {
		t.Errorf(">>> ML-DSA-44 signature verification (nil context) FAILED! Expected true, got false. <<<")
	} else {
		t.Log(">>> ML-DSA-44 signature verification (nil context) successful. <<<")
	}

	// --- Test failure case (wrong message) ---
	t.Log("\nTesting verification failure with wrong message...")
	wrongMessage := []byte("This is NOT the message that was signed.")
	isWrongValid := mldsa44.Verify(pk, wrongMessage, ctx, sig) // Use same pk, nil ctx, original sig
	t.Logf("Verification result (wrong message): %t", isWrongValid)
	if isWrongValid {
		t.Errorf(">>> ML-DSA-44 verification with WRONG message unexpectedly SUCCEEDED! <<<")
	} else {
		t.Log(">>> ML-DSA-44 verification with wrong message correctly failed. <<<")
	}

	// --- Test with non-nil context ---
	t.Log("\nTesting verification with non-nil context...")
	ctxNonNil := []byte("my-application-context-v1")
	t.Logf("Message to sign: %q", string(message))
	t.Logf("Context (ctx): %q", string(ctxNonNil))

	// Re-sign with the non-nil context
	err = mldsa44.SignTo(sk, message, ctxNonNil, useRandomized, sig)
	if err != nil {
		t.Fatalf("Failed to sign message using SignTo (with non-nil context): %v", err)
	}
	t.Logf("Signed message with context. Signature length: %d", len(sig))

	// Verify with the non-nil context
	isValidNonNil := mldsa44.Verify(pk, message, ctxNonNil, sig)
	t.Logf("Verification result (non-nil context): %t", isValidNonNil)
	if !isValidNonNil {
		t.Errorf(">>> ML-DSA-44 signature verification FAILED with non-nil context! <<<")
	} else {
		t.Log(">>> ML-DSA-44 signature verification successful with non-nil context. <<<")
	}

	// --- Test failure with mismatched context ---
	// Verify failure when signature was made with non-nil context, but verified with nil context
	t.Log("\nTesting verification failure with mismatched context (sig has context, verification does not)...")
	// 'sig' currently holds the signature generated with ctxNonNil
	isMismatchCtxValid1 := mldsa44.Verify(pk, message, ctx, sig) // Verifying with nil context (ctx)
	t.Logf("Verification result (mismatched context 1): %t", isMismatchCtxValid1)
	if isMismatchCtxValid1 {
		t.Errorf(">>> ML-DSA-44 verification with MISMATCHED context (sig Ctx, verify nil) unexpectedly SUCCEEDED! <<<")
	} else {
		t.Log(">>> ML-DSA-44 verification with mismatched context (sig Ctx, verify nil) correctly failed. <<<")
	}

	// Sign again with nil context
	err = mldsa44.SignTo(sk, message, ctx, useRandomized, sig)
	if err != nil {
		t.Fatalf("Failed to sign message using SignTo (nil context, prep for mismatch test 2): %v", err)
	}

	// Verify failure when signature was made with nil context, but verified with non-nil context
	t.Log("\nTesting verification failure with mismatched context (sig nil, verification has context)...")
	// 'sig' now holds the signature generated with nil context
	isMismatchCtxValid2 := mldsa44.Verify(pk, message, ctxNonNil, sig) // Verifying with non-nil context
	t.Logf("Verification result (mismatched context 2): %t", isMismatchCtxValid2)
	if isMismatchCtxValid2 {
		t.Errorf(">>> ML-DSA-44 verification with MISMATCHED context (sig nil, verify Ctx) unexpectedly SUCCEEDED! <<<")
	} else {
		t.Log(">>> ML-DSA-44 verification with mismatched context (sig nil, verify Ctx) correctly failed. <<<")
	}
}
