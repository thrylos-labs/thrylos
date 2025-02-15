package chain

// func (bc *BlockchainImpl) calculateAverageLatency() time.Duration {
// 	// This is a placeholder. In a real implementation, you would measure actual network latency.
// 	// For now, we'll return a constant value.
// 	return 200 * time.Millisecond
// }

// func (bc *BlockchainImpl) ResolveForks() {
// 	var longestFork *Fork
// 	longestLength := len(bc.Blocks)
// 	for _, fork := range bc.Forks {
// 		if len(fork.Blocks)+fork.Index > longestLength {
// 			longestLength = len(fork.Blocks) + fork.Index
// 			longestFork = fork
// 		}
// 	}
// 	if longestFork != nil {
// 		// Switch to the longest fork
// 		bc.Blocks = append(bc.Blocks[:longestFork.Index], longestFork.Blocks...)
// 	}
// 	// Clear forks as the longest chain is now the main chain
// 	bc.Forks = nil
// }

// // // Example usage function
// func (bc *BlockchainImpl) CreateNextBlock(nodes ...*node.Node) (*shared.Block, error) {
// 	var node *node.Node
// 	if len(nodes) > 0 {
// 		node = nodes[0]
// 	}

// 	selector := selection.NewValidatorSelector(bc, node)

// 	validator, err := selector.validator.SelectNextValidator()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to select validator: %v", err)
// 	}

// 	return bc.CreateBlockFromPendingTransactions(validator)
// }

// func (bc *BlockchainImpl) SignBlock(block *shared.Block, validatorAddress string) ([]byte, error) {
// 	privateKey, bech32Address, err := bc.GetValidatorPrivateKey(validatorAddress)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get validator private key: %v", err)
// 	}

// 	// The Bech32 address is already returned by GetValidatorPrivateKey, so we don't need to convert it again
// 	block.Validator = bech32Address

// 	blockData, err := block.SerializeForSigning()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to serialize block for signing: %v", err)
// 	}

// 	signature, err := privateKey.Sign(nil, blockData, nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to sign block: %v", err)
// 	}
// 	return signature, nil
// }

// func (bc *BlockchainImpl) VerifySignedBlock(signedBlock *Block) error {
// 	// Verify the block's hash
// 	computedHash := signedBlock.ComputeHash()
// 	if !bytes.Equal(computedHash, signedBlock.Hash) {
// 		log.Printf("Block hash mismatch. Computed: %x, Block: %x", computedHash, signedBlock.Hash)
// 		return errors.New("invalid block hash")
// 	}

// 	publicKey, err := bc.GetValidatorPublicKey(signedBlock.Validator)
// 	if err != nil {
// 		log.Printf("Failed to get validator public key: %v", err)
// 		return fmt.Errorf("failed to get validator public key: %v", err)
// 	}

// 	pubKeyBytes, err := publicKey.MarshalBinary()
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal public key for logging: %v", err)
// 	}
// 	log.Printf("Retrieved public key for verification: %x", pubKeyBytes)

// 	// Also try to retrieve the public key directly from the database
// 	storedPubKeyBytes, err := bc.Database.RetrieveValidatorPublicKey(signedBlock.Validator)
// 	if err != nil {
// 		log.Printf("Failed to retrieve stored public key for validator %s: %v", signedBlock.Validator, err)
// 	} else {
// 		log.Printf("Stored public key for validator %s: %x", signedBlock.Validator, storedPubKeyBytes)

// 		// Create a new public key to unmarshal the stored bytes
// 		storedPublicKey := new(mldsa44.PublicKey)
// 		err = storedPublicKey.UnmarshalBinary(storedPubKeyBytes)
// 		if err != nil {
// 			log.Printf("Failed to unmarshal stored public key: %v", err)
// 		} else {
// 			// Compare the marshaled forms of both keys
// 			currentKeyBytes, _ := publicKey.MarshalBinary()
// 			storedKeyBytes, _ := storedPublicKey.MarshalBinary()
// 			if !bytes.Equal(currentKeyBytes, storedKeyBytes) {
// 				log.Printf("WARNING: Retrieved public key does not match stored public key for validator %s", signedBlock.Validator)
// 			}
// 		}
// 	}

// 	// Verify the signature using MLDSA44
// 	// Note: passing nil as the context parameter as it's not used in the block signing
// 	if !mldsa44.Verify(publicKey, signedBlock.Hash, nil, signedBlock.Signature) {
// 		log.Printf("Signature verification failed. Validator: %s, Block Hash: %x, Signature: %x",
// 			signedBlock.Validator, signedBlock.Hash, signedBlock.Signature)
// 		return errors.New("invalid block signature")
// 	}

// 	log.Printf("Block signature verified successfully for validator: %s", signedBlock.Validator)
// 	return nil
// }

// // // // ValidateBlock checks if the block is valid
// func (bc *BlockchainImpl) ValidateBlock(newBlock *shared.Block, prevBlock *shared.Block) bool {
// 	// Existing checks
// 	if !bytes.Equal(newBlock.PrevHash, prevBlock.Hash) {
// 		fmt.Printf("Invalid previous hash in block %d\n", newBlock.Index)
// 		return false
// 	}

// 	// Add salt validation
// 	if err := bc.validateBlockTransactionSalts(newBlock); err != nil {
// 		fmt.Printf("Invalid transaction salts in block %d: %v\n", newBlock.Index, err)
// 		return false
// 	}

// 	// Rest of existing validation...
// 	if !bc.VerifyPoSRules(*newBlock) {
// 		fmt.Printf("Invalid block %d due to PoS rules: validator was %s\n", newBlock.Index, newBlock.Validator)
// 		return false
// 	}

// 	computedHash := newBlock.ComputeHash()
// 	if !bytes.Equal(newBlock.Hash, computedHash) {
// 		fmt.Printf("Invalid hash in block %d: expected %x, got %x\n", newBlock.Index, computedHash, newBlock.Hash)
// 		return false
// 	}

// 	return true
// }

// // CreateBlock generates a new block with the given transactions, validator, previous hash, and timestamp.
// // This method encapsulates the logic for building a block to be added to the blockchain.
// func (bc *BlockchainImpl) CreateUnsignedBlock(transactions []*thrylos.Transaction, validator string) (shared.Block, error) {
// 	prevBlock := bc.Blockchain.Blocks[len(bc.Blockchain.Blocks)-1]
// 	newBlock := &types.Block{
// 		Index:        int32(len(bc.Blocks)),
// 		Timestamp:    time.Now().Unix(),
// 		Transactions: shartransactions,
// 		Validator:    validator,
// 		PrevHash:     prevBlock.Hash,
// 		// Hash and Signature fields are left empty
// 	}

// 	// Initialize Verkle tree before computing hash
// 	if err := InitializeVerkleTree(); err != nil {
// 		return nil, fmt.Errorf("failed to initialize Verkle tree: %v", err)
// 	}

// 	// Compute the hash
// 	newBlock.Hash = newBlock.ComputeBlockHash()

// 	return newBlock, nil
// }
