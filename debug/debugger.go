package debug

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// SignatureDebugger helps diagnose transaction signature issues
type SignatureDebugger struct {
	logger *log.Logger
}

func NewSignatureDebugger() *SignatureDebugger {
	return &SignatureDebugger{
		logger: log.Default(),
	}
}

func (d *SignatureDebugger) DebugSignature(tx map[string]interface{}, signature, publicKey []byte) error {
	// Create sorted canonical form first
	sortedPayload := d.sortMapToJSON(tx)

	// Marshal the sorted payload
	canonicalData, err := json.Marshal(sortedPayload)
	if err != nil {
		return fmt.Errorf("canonical data creation failed: %v", err)
	}

	d.logger.Printf("=== Detailed Signature Debug ===")
	d.logger.Printf("1. Original Payload: %+v", tx)
	d.logger.Printf("2. Sorted Payload: %+v", sortedPayload)
	d.logger.Printf("3. Canonical JSON: %s", string(canonicalData))
	d.logger.Printf("4. Message bytes (hex): %x", canonicalData)
	d.logger.Printf("5. Signature (hex): %x", signature)
	d.logger.Printf("6. Public Key (hex): %x", publicKey)

	pk := new(mldsa44.PublicKey)
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	// Verify signature
	if !mldsa44.Verify(pk, canonicalData, signature, nil) {
		d.logger.Printf("❌ Signature Verification Failed")
		return fmt.Errorf("signature verification failed")
	}

	d.logger.Printf("✅ Signature Verification Succeeded")
	return nil
}

func (d *SignatureDebugger) sortMapToJSON(m map[string]interface{}) map[string]interface{} {
	sorted := make(map[string]interface{})
	keys := make([]string, 0, len(m))

	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := m[k]
		// Handle nested maps
		if nestedMap, ok := v.(map[string]interface{}); ok {
			sorted[k] = d.sortMapToJSON(nestedMap)
		} else if nestedSlice, ok := v.([]interface{}); ok {
			// Handle slices of maps
			for i, item := range nestedSlice {
				if nestedMap, ok := item.(map[string]interface{}); ok {
					nestedSlice[i] = d.sortMapToJSON(nestedMap)
				}
			}
			sorted[k] = nestedSlice
		} else {
			sorted[k] = v
		}
	}
	return sorted
}

// Helper function to compare two canonical forms
func (d *SignatureDebugger) CompareCanonicalForms(expected, actual []byte) {
	d.logger.Printf("=== Canonical Form Comparison ===")
	if len(expected) != len(actual) {
		d.logger.Printf("Length mismatch: expected %d, got %d", len(expected), len(actual))
	}

	minLen := len(expected)
	if len(actual) < minLen {
		minLen = len(actual)
	}

	for i := 0; i < minLen; i++ {
		if expected[i] != actual[i] {
			d.logger.Printf("Mismatch at position %d: expected %x, got %x", i, expected[i], actual[i])
		}
	}
}
