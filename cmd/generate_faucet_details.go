package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	// Make sure these import paths are correct for your project setup
	// If running this utility from a directory that can't find thrylos-labs/thrylos,
	// you might need to set up a temporary go.mod or run it within a project
	// that has thrylos as a dependency.
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	thrylosCrypto "github.com/thrylos-labs/thrylos/crypto"
)

func main() {
	var seedArray [mldsa44.SeedSize]byte // mldsa44.SeedSize is typically 32
	if _, err := rand.Read(seedArray[:]); err != nil {
		log.Fatalf("Failed to generate seed: %v", err)
	}

	hexSeed := hex.EncodeToString(seedArray[:])
	fmt.Printf("Generated Hex Seed: %s\n", hexSeed)

	// Derive keys from the seed
	// mldsa44.NewKeyFromSeed returns (*mldsa44.PublicKey, *mldsa44.PrivateKey)
	rawMldsaPK, rawMldsaSK := mldsa44.NewKeyFromSeed(&seedArray)
	if rawMldsaPK == nil || rawMldsaSK == nil {
		log.Fatalf("mldsa44.NewKeyFromSeed returned nil key(s)")
	}

	// Wrap with Thrylos crypto types
	thrylosSK := thrylosCrypto.NewPrivateKeyFromMLDSA(rawMldsaSK)
	if thrylosSK == nil {
		log.Fatalf("thrylosCrypto.NewPrivateKeyFromMLDSA returned nil for private key")
	}
	thrylosPK := thrylosSK.PublicKey()
	if thrylosPK == nil {
		log.Fatalf("thrylosSK.PublicKey() returned nil")
	}

	// Derive Thrylos Address String
	addrObj, err := thrylosPK.Address()
	if err != nil {
		log.Fatalf("could not get address object from thrylos public key: %v", err)
	}
	if addrObj == nil {
		log.Fatalf("thrylosPK.Address() returned a nil address object")
	}
	addressStr := addrObj.String()
	if addressStr == "" {
		log.Fatalf("derived empty address string")
	}

	fmt.Printf("Corresponding Thrylos Faucet Address: %s\n\n", addressStr)
	fmt.Println("---------------------------------------------------------------------------")
	fmt.Println("IMPORTANT SETUP INSTRUCTIONS:")
	fmt.Println("1. Copy the 'Generated Hex Seed' printed above.")
	fmt.Println("2. Use this hex seed for the -faucet-seed flag when running the load generator.")
	fmt.Println("   Example: ./load_generator -faucet-seed <PASTE_HEX_SEED_HERE> ...other_flags...")
	fmt.Println("3. CRITICAL: Before running the load generator, you MUST ensure the")
	fmt.Println("   'Corresponding Thrylos Faucet Address' (also printed above) is pre-funded")
	fmt.Println("   with a large amount of tokens in your Thrylos blockchain's genesis block.")
	fmt.Println("   The load generator needs this account to have funds to distribute to worker accounts.")
	fmt.Println("---------------------------------------------------------------------------")
}
