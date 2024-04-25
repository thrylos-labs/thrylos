package main

import (
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/joho/godotenv"
)

// TestWasmIntegration checks if the WebAssembly module functions as expected within the blockchain context.
func TestWasmIntegration(t *testing.T) {
	// Specify the path to your .env file relative to the location from where the tests are run
	envPath := "../../.env"
	if err := godotenv.Load(envPath); err != nil {
		log.Fatalf("Error loading .env file from %s: %v", envPath, err)
	}

	// Get the path to the Wasm file from the environment variable
	wasmPath := os.Getenv("WASM_PATH")
	if wasmPath == "" {
		log.Fatal("WASM_PATH environment variable not set")
	}

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
