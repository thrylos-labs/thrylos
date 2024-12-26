package core

// var (
// 	publicKeyCache sync.Map
// )

// func (node *Node) RetrievePublicKey(address string) (ed25519.PublicKey, error) {
// 	log.Printf("Attempting to retrieve public key for address: %s", address)

// 	// Try RetrievePublicKeyFromAddress first
// 	pubKey, err := node.Blockchain.Database.RetrievePublicKeyFromAddress(address)
// 	if err == nil {
// 		log.Printf("Public key retrieved using RetrievePublicKeyFromAddress for address: %s", address)
// 		return pubKey, nil
// 	}
// 	log.Printf("RetrievePublicKeyFromAddress failed for %s: %v, trying RetrieveEd25519PublicKey", address, err)

// 	// If that fails, try RetrieveEd25519PublicKey
// 	pubKey, err = node.Blockchain.Database.RetrieveEd25519PublicKey(address)
// 	if err == nil {
// 		log.Printf("Public key retrieved using RetrieveEd25519PublicKey for address: %s", address)

// 		// Optionally migrate the key to the new format
// 		if migrateErr := node.Blockchain.Database.InsertOrUpdateEd25519PublicKey(address, pubKey); migrateErr != nil {
// 			log.Printf("Warning: Failed to migrate public key format for %s: %v", address, migrateErr)
// 			// Don't return error here as we still have the key
// 		}

// 		return pubKey, nil
// 	}

// 	// If both methods fail, return the error
// 	log.Printf("Failed to retrieve public key using both methods for address: %s, errors: %v", address, err)
// 	return nil, fmt.Errorf("public key not found for address: %s using either retrieval method", address)
// }

// func (node *Node) StorePublicKey(address string, publicKey ed25519.PublicKey) {
// 	node.PublicKeyMap[address] = publicKey
// }
