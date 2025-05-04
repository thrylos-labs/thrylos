// generate_key.go (Temporary tool)
package main

// You might also need the address logic if you want to print the address
// "github.com/thrylos-labs/thrylos/crypto/address"

// func main() {
// 	fmt.Println("Generating new persistent Genesis key pair...")

// 	// 1. Generate a new private key using your crypto package
// 	privKey, err := crypto.NewPrivateKey()
// 	if err != nil {
// 		log.Fatalf("FATAL: Failed to generate private key: %v", err)
// 	}

// 	// 2. Marshal the private key (this performs CBOR encoding internally)
// 	cborBytes, err := privKey.Marshal()
// 	if err != nil {
// 		log.Fatalf("FATAL: Failed to marshal private key to CBOR: %v", err)
// 	}

// 	// 3. Base64 encode the CBOR bytes
// 	privKeyBase64 := base64.StdEncoding.EncodeToString(cborBytes)

// 	// 4. (Optional) Get the corresponding address
// 	var addrStr string = "Could not derive address"
// 	if pubKey := privKey.PublicKey(); pubKey != nil {
// 		addr, errAddr := pubKey.Address()
// 		if errAddr == nil {
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
// 	fmt.Println("\nEnvironment Variable Name: GENESIS_PRIVATE_KEY_CBOR_B64")
// 	fmt.Println("\nValue (Base64 encoded CBOR):")
// 	fmt.Printf("\n%s\n\n", privKeyBase64) // Print the key string clearly
// 	fmt.Println("---------------------------")

// }
