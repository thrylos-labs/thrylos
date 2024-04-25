package main

import (
	"io/ioutil"
	"testing"
)

// TestWasmIntegration checks if the WebAssembly module functions as expected within the blockchain context.
func TestWasmIntegration(t *testing.T) {
	// Path to the Wasm file generated from Rust
	wasmPath := "/Users/ned/Documents/GitHub/rust_wasm/target/wasm32-unknown-unknown/release/rust_wasm.wasm"

	// Load the WebAssembly binary
	wasmBytes, err := ioutil.ReadFile(wasmPath)
	if err != nil {
		t.Fatalf("Failed to read wasm file: %v", err)
	}

	// Execute the WebAssembly module
	result := executeWasm(wasmBytes)
	expectedResult := 20 // Adjust based on your expectations and what process_transaction does

	// Verify the result
	if result != expectedResult {
		t.Errorf("Wasm execution failed, expected %d, got %d", expectedResult, result)
	}
}
