package core

import (
	"Thrylos/shared"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

func TestNewBlockchain(t *testing.T) {
	bc, err := NewBlockchain()
	if err != nil {
		t.Fatalf("Failed to create blockchain: %v", err)
	}

	if bc.Genesis == nil {
		t.Errorf("Genesis block is nil")
	}
	// Further checks can include validating the initial state of the blockchain, such as the number of blocks, initial UTXOs, etc.
}

func TestTransactionSignatureVerificationWithDifferentKey(t *testing.T) {
	privateKey1, _, err := shared.GenerateRSAKeys(2048)
	if err != nil {
		t.Fatalf("Error generating first RSA key pair: %v", err)
	}

	_, publicKey2, err := shared.GenerateRSAKeys(2048) // Different key pair
	if err != nil {
		t.Fatalf("Error generating second RSA key pair: %v", err)
	}

	tx, err := shared.CreateMockSignedTransaction("txDifferentKey", privateKey1)
	if err != nil {
		t.Fatalf("Error creating mock signed transaction: %v", err)
	}

	err = shared.VerifyTransactionSignature(&tx, publicKey2)
	if err == nil {
		t.Error("Verification succeeded for transaction signed with a different key")
	}
}

func TestValidTransactionSignatureVerification(t *testing.T) {
	privateKey, publicKey, err := shared.GenerateRSAKeys(2048)
	if err != nil {
		t.Fatalf("Error generating RSA key pair: %v", err)
	}

	tx, err := shared.CreateMockSignedTransaction("txValid", privateKey)
	if err != nil {
		t.Fatalf("Error creating mock signed transaction: %v", err)
	}

	err = shared.VerifyTransactionSignature(&tx, publicKey)
	if err != nil {
		t.Errorf("Failed to verify valid transaction signature: %v", err)
	}
}

func TestManualSigningAndVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Example data to sign
	data := "This is a test."
	hashed := sha256.Sum256([]byte(data))

	// Sign the data
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Verify the signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	} else {
		t.Log("Signature verification succeeded.")
	}
}

func TestAddBlockWithVerifiedTransactions(t *testing.T) {
	bc, err := NewBlockchain()
	if err != nil {
		t.Fatalf("Failed to initialize blockchain: %v", err)
	}

	privateKey, _, err := shared.GenerateRSAKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Create a mock signed transaction
	tx, err := shared.CreateMockSignedTransaction("tx1", privateKey)
	if err != nil {
		t.Fatalf("Failed to create mock signed transaction: %v", err)
	}

	// Correct handling of the VerifyTransaction function
	verified, err := shared.VerifyTransaction(tx, bc.UTXOs, func(address string) (*rsa.PublicKey, error) {
		// Here, ensure that the public key retrieval is implemented according to your application's logic
		return &privateKey.PublicKey, nil
	})
	if !verified || err != nil {
		t.Fatalf("Transaction verification failed: %v", err)
	}

	// Add the verified transaction to a new block
	transactions := []shared.Transaction{tx}
	prevHash := bc.Blocks[len(bc.Blocks)-1].Hash // Assuming there is at least one block (the genesis block)
	_, err = bc.AddBlock(transactions, "validator1", prevHash)
	if err != nil {
		t.Fatalf("Failed to add block with transactions: %v", err)
	}

	// Assertions to verify the block was added successfully and the blockchain length increased
	if len(bc.Blocks) != 2 { // Expecting genesis block + new block
		t.Errorf("Expected blockchain length of 2, got %d", len(bc.Blocks))
	}
}
