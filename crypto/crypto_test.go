// crypto_test.go (Revised to match interfaces.go)
package crypto

import (
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	if privKey == nil {
		t.Fatalf("NewPrivateKey returned nil")
	}
	t.Logf("Key generation successful. Type: %T, String: %s", privKey, privKey.String())
}

func TestPublicKey(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	pubKey1 := privKey.PublicKey()
	if pubKey1 == nil {
		t.Fatalf("privKey.PublicKey() returned nil")
	}
	t.Logf("PublicKey1 generated. String: %s", pubKey1.String())

	marshaledPubKey, err := pubKey1.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pubKey2, err := NewPublicKeyFromBytes(marshaledPubKey)
	if err != nil {
		t.Fatalf("NewPublicKeyFromBytes failed: %v", err)
	}
	if pubKey2 == nil {
		t.Fatalf("NewPublicKeyFromBytes returned nil key")
	}
	t.Logf("PublicKey2 unmarshaled. String: %s", pubKey2.String())

	// Compare using the Equal method which takes *PublicKey
	if !pubKey1.Equal(&pubKey2) { // Pass pointer to interface
		t.Errorf("Public keys should be equal after marshal/unmarshal")
		t.Logf("PubKey1 bytes: %x", pubKey1.Bytes())
		t.Logf("PubKey2 bytes: %x", pubKey2.Bytes())
	} else {
		t.Log("Public key equality after marshal/unmarshal verified.")
	}
}

func TestSigningAndVerification(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	pubKey := privKey.PublicKey()
	if pubKey == nil {
		t.Fatalf("Failed to get public key from private key")
	}

	msg := []byte("test message for signing and verification")

	// Sign message - Sign returns Signature (no error)
	sig := privKey.Sign(msg)
	if sig == nil {
		// If Sign panics/fatals, this won't be reached.
		// If NewSignature returned nil inside Sign, this catches it.
		t.Fatalf("Sign returned nil signature")
	}
	t.Logf("Signing successful. Signature: %s", sig.String())

	// Verify using PublicKey.Verify (takes *Signature, returns error)
	err = pubKey.Verify(msg, &sig) // Pass pointer to interface
	if err != nil {
		t.Errorf("Verification failed using pubKey.Verify: %v", err)
	} else {
		t.Log("Verification successful using pubKey.Verify.")
	}

	// Verify using Signature.Verify (takes *PublicKey, returns error)
	err = sig.Verify(&pubKey, msg) // Pass pointer to interface
	if err != nil {
		t.Errorf("Verification failed using sig.Verify: %v", err)
	} else {
		t.Log("Verification successful using sig.Verify.")
	}

	// Test verification failure with wrong message
	wrongMsg := []byte("this is not the correct message")
	err = pubKey.Verify(wrongMsg, &sig) // Pass pointer
	if err == nil {
		t.Errorf("Verification SUCCEEDED with wrong message using pubKey.Verify, expected failure")
	} else {
		t.Logf("Verification correctly failed with wrong message using pubKey.Verify: %v", err)
	}

	// Test verification failure with wrong key
	privKeyWrong, _ := NewPrivateKey()
	pubKeyWrong := privKeyWrong.PublicKey()
	if pubKeyWrong == nil {
		t.Fatalf("Failed to get wrong public key")
	}
	err = pubKeyWrong.Verify(msg, &sig) // Pass pointer
	if err == nil {
		t.Errorf("Verification SUCCEEDED with wrong public key, expected failure")
	} else {
		t.Logf("Verification correctly failed with wrong public key: %v", err)
	}
}

func TestSignatureComparison(t *testing.T) {
	privKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	msg := []byte("test message for signature comparison")

	sig1 := privKey.Sign(msg)
	sig2 := privKey.Sign(msg)
	if sig1 == nil || sig2 == nil {
		t.Fatalf("Sign returned nil signature(s)")
	}

	// Test self-equality (takes Signature)
	if !sig1.Equal(sig1) {
		t.Errorf("Signature should be equal to itself (sig1.Equal(sig1))")
	} else {
		t.Log("Signature self-equality verified.")
	}

	// Test equality of deterministic signatures (takes Signature)
	if !sig1.Equal(sig2) {
		t.Errorf("Deterministic signatures of the same message should be EQUAL, but sig1 != sig2")
		t.Logf("Sig1 bytes: %x", sig1.Bytes())
		t.Logf("Sig2 bytes: %x", sig2.Bytes())
	} else {
		t.Log("Equality of deterministic signatures verified.")
	}

	// Test inequality with signature of different message
	msg2 := []byte("a different message")
	sig3 := privKey.Sign(msg2)
	if sig3 == nil {
		t.Fatalf("Third Sign returned nil signature")
	}
	if sig1.Equal(sig3) {
		t.Errorf("Signatures of different messages should be different, but sig1 == sig3")
	} else {
		t.Log("Inequality of signatures from different messages verified.")
	}
}

func TestKeyMarshaling(t *testing.T) {
	privKey1, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	pubKey1 := privKey1.PublicKey()
	if pubKey1 == nil {
		t.Fatalf("PublicKey was nil")
	}

	// Marshal/Unmarshal Private Key
	marshaledPriv, err := privKey1.Marshal()
	if err != nil {
		t.Fatalf("privKey1.Marshal() failed: %v", err)
	}
	privKey2, err := NewPrivateKeyFromBytes(marshaledPriv)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromBytes failed: %v", err)
	}
	if privKey2 == nil {
		t.Fatalf("NewPrivateKeyFromBytes returned nil")
	}

	// Compare Private Keys (Equal takes *PrivateKey)
	if !privKey1.Equal(&privKey2) { // Pass pointer
		t.Errorf("Private keys should be equal after marshal/unmarshal")
		t.Logf("PrivKey1 bytes: %x", privKey1.Bytes())
		t.Logf("PrivKey2 bytes: %x", privKey2.Bytes())
	} else {
		t.Log("Private key marshal/unmarshal successful.")
	}

	// Marshal/Unmarshal Public Key
	marshaledPub, err := pubKey1.Marshal()
	if err != nil {
		t.Fatalf("pubKey1.Marshal() failed: %v", err)
	}
	pubKey2, err := NewPublicKeyFromBytes(marshaledPub)
	if err != nil {
		t.Fatalf("NewPublicKeyFromBytes failed: %v", err)
	}
	if pubKey2 == nil {
		t.Fatalf("NewPublicKeyFromBytes returned nil")
	}

	// Compare Public Keys (Equal takes *PublicKey)
	if !pubKey1.Equal(&pubKey2) { // Pass pointer
		t.Errorf("Public keys should be equal after marshal/unmarshal")
		t.Logf("PubKey1 bytes: %x", pubKey1.Bytes())
		t.Logf("PubKey2 bytes: %x", pubKey2.Bytes())
	} else {
		t.Log("Public key marshal/unmarshal successful.")
	}
}

func TestSignatureMarshaling(t *testing.T) {
	privKey, _ := NewPrivateKey()
	msg := []byte("message for signature marshal test")
	sig1 := privKey.Sign(msg)
	if sig1 == nil {
		t.Fatalf("Sign returned nil signature")
	}

	marshaledSig, err := sig1.Marshal()
	if err != nil {
		t.Fatalf("sig1.Marshal() failed: %v", err)
	}

	// Need a way to unmarshal bytes directly into a Signature interface
	// Let's create a helper function or use the concrete type's Unmarshal
	var sig2Impl signature
	err = sig2Impl.Unmarshal(marshaledSig) // Unmarshal into concrete type
	if err != nil {
		t.Fatalf("sig2Impl.Unmarshal failed: %v", err)
	}
	// Now compare sig1 (interface) with sig2Impl (concrete) using Equal
	sig2 := Signature(&sig2Impl) // Get interface value for comparison

	if !sig1.Equal(sig2) { // Equal takes Signature interface value
		t.Errorf("Signature objects mismatch after marshal/unmarshal")
		t.Logf("Sig1: %s, Bytes: %x", sig1.String(), sig1.Bytes())
		t.Logf("Sig2: %s, Bytes: %x", sig2.String(), sig2.Bytes())
	} else {
		t.Log("Signature objects equal after marshal/unmarshal.")
	}
}
