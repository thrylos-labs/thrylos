// generate_key.go (Temporary tool)
package main

// func main() {
// 	fmt.Println("Generating new persistent Genesis key pair...")

// 	// 1. Generate a new private key using your crypto package
// 	privKey, err := crypto.NewPrivateKey()
// 	if err != nil {
// 		log.Fatalf("FATAL: Failed to generate private key: %v", err)
// 	}

// 	// 2. Get the RAW private key bytes directly
// 	// CORRECTED: Bytes() returns only one value ([]byte)
// 	rawBytes := privKey.Bytes()
// 	// Add a check in case Bytes() returns nil for some reason
// 	if rawBytes == nil {
// 		log.Fatalf("FATAL: Failed to get raw bytes from generated private key")
// 	}
// 	// REMOVED: Error check 'if err != nil {...}'

// 	// 3. Base64 encode the RAW bytes
// 	privKeyBase64 := base64.StdEncoding.EncodeToString(rawBytes)

// 	// 4. (Optional) Get the corresponding address
// 	var addrStr string = "Could not derive address"
// 	if pubKey := privKey.PublicKey(); pubKey != nil {
// 		// Assuming Address() returns (*address.Address, error)
// 		addr, errAddr := pubKey.Address()
// 		if errAddr == nil && addr != nil { // Check addr is not nil too
// 			addrStr = addr.String()
// 		} else {
// 			addrStr = fmt.Sprintf("Error deriving address: %v", errAddr)
// 		}
// 	}

// 	// --- Output ---
// 	fmt.Println("\n--- GENERATED GENESIS KEY ---")
// 	fmt.Printf("Corresponding Address: %s\n", addrStr)
// 	fmt.Println("\nKEEP THE PRIVATE KEY STRING SECRET AND SECURE!")
// 	fmt.Println("Store it as an environment variable (e.g., in your .env file)")
// 	// --- Suggest using a new environment variable name ---
// 	fmt.Println("\nRecommended Environment Variable Name: GENESIS_PRIVATE_KEY_RAW_B64")
// 	fmt.Println("\nValue (Base64 encoded RAW bytes):")
// 	fmt.Printf("\n%s\n\n", privKeyBase64) // Print the key string clearly
// 	fmt.Println("---------------------------")

// }
