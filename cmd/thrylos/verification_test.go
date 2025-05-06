package main

// func RunMinimalCryptoTest() {
// 	fmt.Println("--- Running Minimal Crypto Verification Test (v6 - Using Actual Key & Raw Bytes Logic) ---")

// 	// --------------------------------------------------------------------
// 	// 1. Define Input Data (Using the key from your .env)
// 	// --------------------------------------------------------------------
// 	// This is the Base64 string from your .env file, representing RAW private key bytes
// 	base64RawPrivKey := "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"

// 	// --------------------------------------------------------------------
// 	// 2. Load Private Key (Handling RAW bytes)
// 	// --------------------------------------------------------------------
// 	rawPrivKeyBytes, err := base64.StdEncoding.DecodeString(base64RawPrivKey)
// 	if err != nil {
// 		log.Fatalf("Failed to base64 decode private key string: %v", err)
// 	}

// 	// Use the Unmarshal method of the concrete implementation (assuming it's exported or accessible)
// 	// If PrivateKeyImpl is not exported, you need a factory function like NewPrivateKeyFromRawBytes
// 	privKeyImpl := &crypto.PrivateKeyImpl{}      // Instantiate the concrete (exported) type
// 	err = privKeyImpl.Unmarshal(rawPrivKeyBytes) // Call Unmarshal which expects raw bytes
// 	if err != nil {
// 		log.Fatalf("Failed to unmarshal raw private key bytes: %v", err)
// 	}
// 	privKey := crypto.PrivateKey(privKeyImpl) // Assign to the interface type
// 	log.Println("Successfully loaded private key from raw bytes.")

// 	// --------------------------------------------------------------------
// 	// 3. Derive Public Key Directly using your crypto package method
// 	// --------------------------------------------------------------------
// 	pubKey := privKey.PublicKey() // Returns crypto.PublicKey interface
// 	if pubKey == nil {
// 		log.Fatal("Failed to derive public key from private key (returned nil).")
// 	}
// 	log.Println("Successfully derived public key directly.")

// 	// --------------------------------------------------------------------
// 	// 4. Define Sample Message Hash
// 	// --------------------------------------------------------------------
// 	// In the real scenario, this would be the block hash bytes
// 	messageHashBytes := []byte("this represents the block hash to be signed and verified")
// 	log.Printf("Using sample message hash: %x\n", messageHashBytes)

// 	// --------------------------------------------------------------------
// 	// 5. Sign the Hash using your crypto package method
// 	// --------------------------------------------------------------------
// 	signature := privKey.Sign(messageHashBytes) // Returns crypto.Signature interface
// 	if signature == nil {
// 		log.Fatal("Failed to sign message hash (signature is nil).")
// 	}
// 	sigBytes := signature.Bytes()
// 	if len(sigBytes) == 0 {
// 		log.Fatal("Failed to sign message hash (signature bytes are empty).")
// 	}
// 	log.Printf("Successfully signed message hash. Signature bytes length: %d\n", len(sigBytes))

// 	// --------------------------------------------------------------------
// 	// 6. Immediate Verification (Using directly derived key and crypto interface)
// 	// --------------------------------------------------------------------
// 	// The Verify method is on the signature object and takes a *pointer* to the PublicKey interface
// 	errImmediate := signature.Verify(&pubKey, messageHashBytes) // Pass pointer to interface
// 	isValidImmediate := errImmediate == nil
// 	log.Printf("IMMEDIATE Verification Result (using derived key): %v (Error: %v)\n", isValidImmediate, errImmediate)

// 	// --------------------------------------------------------------------
// 	// 7. Marshal Public Key to Bytes using crypto interface method
// 	// --------------------------------------------------------------------
// 	// Use the Marshal method defined in the interface (expects raw bytes output)
// 	marshalledPubKeyBytes, errMarshal := pubKey.Marshal() // Use the interface method
// 	if errMarshal != nil {
// 		log.Fatalf("Failed to marshal public key to bytes: %v", errMarshal)
// 	}
// 	if len(marshalledPubKeyBytes) == 0 {
// 		log.Fatal("Marshalled public key bytes are empty.")
// 	}
// 	log.Printf("Successfully marshalled public key (raw bytes). Bytes length: %d\n", len(marshalledPubKeyBytes))

// 	// --------------------------------------------------------------------
// 	// 8. Unmarshal Bytes into a NEW Public Key Object using the Factory Function
// 	// --------------------------------------------------------------------
// 	// Use the exported NewPublicKeyFromBytes function (expects raw bytes input)
// 	newPubKey, errUnmarshal := crypto.NewPublicKeyFromBytes(marshalledPubKeyBytes)
// 	if errUnmarshal != nil {
// 		// This function already calls the internal Unmarshal method
// 		log.Fatalf("Failed to create new public key from bytes using NewPublicKeyFromBytes: %v", errUnmarshal)
// 	}
// 	// 'newPubKey' is now a crypto.PublicKey interface containing the unmarshalled key
// 	log.Println("Successfully created new public key object from bytes.")

// 	// --------------------------------------------------------------------
// 	// 9. Verification using the UNMARSHALLED Key
// 	// --------------------------------------------------------------------
// 	// Call Verify on the original signature object, passing a pointer to the *new* PublicKey interface variable
// 	errUnmarshalVerify := signature.Verify(&newPubKey, messageHashBytes) // Pass pointer to the new interface variable
// 	isValidAfterUnmarshal := errUnmarshalVerify == nil
// 	log.Printf("Verification Result (using UNMARSHALLED key): %v (Error: %v)\n", isValidAfterUnmarshal, errUnmarshalVerify)

// 	// --------------------------------------------------------------------
// 	// 10. Compare Results
// 	// --------------------------------------------------------------------
// 	fmt.Println("--- Test Summary ---")
// 	fmt.Printf("Immediate Verification Passed: %v\n", isValidImmediate)
// 	fmt.Printf("Verification After Unmarshal Passed: %v\n", isValidAfterUnmarshal)

// 	if isValidImmediate && isValidAfterUnmarshal {
// 		fmt.Println("✅ SUCCESS: Both verification steps passed. The core crypto signing/verification and key marshalling/unmarshalling (using raw bytes) via your crypto package seem OK.")
// 		fmt.Println("   The issue in the blockchain likely lies elsewhere (e.g., incorrect key retrieval logic for the specific validator address, hash data mismatch despite logs, state corruption).")
// 	} else if isValidImmediate && !isValidAfterUnmarshal {
// 		fmt.Println("❌ FAILURE: Verification failed ONLY after marshalling/unmarshalling the public key.")
// 		fmt.Println("   This strongly suggests an issue with how the public key is stored/retrieved OR with the Marshal/Unmarshal implementation (expecting raw bytes) in your crypto package, or the NewPublicKeyFromBytes function.")
// 		fmt.Println("   Double-check your Store's SavePublicKey/GetPublicKey implementation and the Marshal/Unmarshal methods and NewPublicKeyFromBytes.")
// 	} else {
// 		fmt.Println("❌ FAILURE: Immediate verification failed. There's a fundamental issue in the signing/verification logic within your crypto package wrappers or the key loading.")
// 		fmt.Println("   Check the crypto.NewPrivateKeyFromBytes, privKey.Sign, and signature.Verify methods.")
// 	}
// 	fmt.Println("-----------------------------------------------------")
// }
