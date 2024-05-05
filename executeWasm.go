package thrylos

import (
	"log"

	"github.com/wasmerio/wasmer-go/wasmer"
)

func ExecuteWasm(wasmBytes []byte) int {
	// Create an instance of the WebAssembly engine
	engine := wasmer.NewEngine()
	store := wasmer.NewStore(engine)

	// Compile the WebAssembly module
	module, err := wasmer.NewModule(store, wasmBytes)
	if err != nil {
		log.Fatalf("Failed to compile module: %v", err)
	}

	// Create an instance of the module
	instance, err := wasmer.NewInstance(module, wasmer.NewImportObject())
	if err != nil {
		log.Fatalf("Failed to instantiate wasm module: %v", err)
	}

	// Get the `process_transaction` function from the module
	processTransaction, err := instance.Exports.GetFunction("process_transaction")
	if err != nil {
		log.Fatalf("Failed to get process_transaction function: %v", err)
	}

	// Call the WebAssembly function
	result, err := processTransaction(10) // passing an example value
	if err != nil {
		log.Fatalf("Failed to execute process_transaction function: %v", err)
	}

	// Assuming the function returns an i32 and converting it properly
	if processedResult, ok := result.(int32); ok {
		return int(processedResult) // convert int32 to int
	} else {
		log.Fatalf("Failed to convert result to int32")
		return 0
	}
}
