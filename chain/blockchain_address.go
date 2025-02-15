package chain

// func generateBech32Address(publicKey *mldsa44.PublicKey) (string, error) {
// 	// First marshal the public key to bytes
// 	pubKeyBytes, err := publicKey.MarshalBinary()
// 	if err != nil {
// 		return "", fmt.Errorf("failed to marshal public key: %v", err)
// 	}

// 	// Generate SHA256 hash of the marshaled public key
// 	hash := sha256.Sum256(pubKeyBytes)

// 	// Take first 20 bytes of the hash for the address
// 	converted, err := bech32.ConvertBits(hash[:20], 8, 5, true)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to convert bits for Bech32 address: %v", err)
// 	}

// 	// Encode with tl1 prefix
// 	bech32Address, err := bech32.Encode("tl1", converted)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to encode Bech32 address: %v", err)
// 	}

// 	return bech32Address, nil
// }

// // not sure if needed
// func (bc *BlockchainImpl) GetChainID() string {
// 	return "tl1" // Mainnet (adjust as per your chain)
// }
