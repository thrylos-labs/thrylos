package crypto

import (
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	_, ok := privKey.(privateKey)
	if !ok {
		t.Logf("invalid private key")
	}
}
func TestPublicKey(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	pubKey1, ok := privKey.PublicKey().(publicKey)
	if !ok {
		t.Logf("invalid public key")
	}
	pubKey2 := NewPublicKey(pubKey1.pubKey)

	if !pubKey1.Equal(&pubKey2) {
		t.Errorf("Public key mismatch")
	}
}

func TestSigningAndVerification(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	pubKey := privKey.PublicKey()

	msg := []byte("test message")
	sig := privKey.Sign(msg)
	if sig == nil {
		t.Fatalf("Signature should not be nil")
	}

	err = pubKey.Verify(msg, &sig)
	if err != nil {
		t.Errorf("Verification failed: %v", err)
	}
}

func TestSignatureComparison(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	msg := []byte("test message")
	sig1 := privKey.Sign(msg)
	sig2 := privKey.Sign(msg)

	if !sig1.Equal(sig1) {
		t.Errorf("Signature should be equal to itself")
	}

	if sig1.Equal(sig2) {
		t.Errorf("Two signatures of the same message should be different")
	}
}
