package mldsa44

import (
	"testing"

	mldsa "github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

func TestKeyGeneration(t *testing.T) {
	pk, sk, err := mldsa.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	privKey := &PrivateKey{sk: *sk}
	pubKey := privKey.PublicKey()

	if !pubKey.pk.Equal(&PublicKey{pk: *pk}) {
		t.Errorf("Public key mismatch")
	}
}

func TestSigningAndVerification(t *testing.T) {
	pk, sk, err := mldsa.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	privKey := &PrivateKey{sk: *sk}
	pubKey := &PublicKey{pk: *pk}

	msg := []byte("test message")
	sig := privKey.Sign(msg)
	if sig == nil {
		t.Fatalf("Signature should not be nil")
	}

	err = pubKey.Verify(msg, sig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
}

func TestSignatureComparison(t *testing.T) {
	_, sk, err := mldsa.GenerateKey(nil)
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	privKey := &PrivateKey{sk: *sk}
	msg := []byte("test message")
	sig1 := privKey.Sign(msg)
	sig2 := privKey.Sign(msg)

	if !sig1.Equal(*sig1) {
		t.Errorf("Signature should be equal to itself")
	}

	if sig1.Equal(*sig2) {
		t.Errorf("Two signatures of the same message should be different")
	}
}
