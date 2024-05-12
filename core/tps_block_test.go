package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/thrylos-labs/thrylos" // ensure this import path is correct

	// ensure this import path is correct

	"github.com/thrylos-labs/thrylos/shared"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// go test -v -timeout 30s -run ^TestTransactionThroughput$ github.com/thrylos-labs/thrylos/core

func TestTransactionThroughput(t *testing.T) {
	// Generate Ed25519 keys
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Ed25519 key pair: %v", err)
	}

	// Define the number of transactions to simulate
	numTransactions := 1000

	start := time.Now()

	for i := 0; i < numTransactions; i++ {
		// Simulate creating a transaction
		txID := fmt.Sprintf("tx%d", i)
		inputs := []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}}
		outputs := []shared.UTXO{{TransactionID: txID, Index: 0, OwnerAddress: "Bob", Amount: 100}}
		tx := shared.Transaction{ID: txID, Inputs: inputs, Outputs: outputs, Timestamp: time.Now().Unix()}

		// Serialize the transaction (excluding the signature for now)
		txBytes, _ := json.Marshal(tx)

		// Sign the serialized transaction data directly with Ed25519 (no separate hashing needed)
		signature := ed25519.Sign(privateKey, txBytes)

		// Verify the signature with the Ed25519 public key
		if !ed25519.Verify(publicKey, txBytes, signature) {
			t.Fatalf("Signature verification failed at transaction %d", i)
		}
	}

	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()

	t.Logf("Processed %d transactions in %s. TPS: %f", numTransactions, elapsed, tps)
}

// go test -v -timeout 30s -run ^TestTransactionThroughputWithAllSignatures$ github.com/thrylos-labs/thrylos/core

func TestTransactionThroughputWithAllSignatures(t *testing.T) {
	// Generate Ed25519 keys
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Ed25519 key pair: %v", err)
	}

	// Define the number of transactions and the size of each batch
	numTransactions := 1000
	batchSize := 20 // Define an appropriate batch size

	start := time.Now()

	var wg sync.WaitGroup

	// Process transactions in batches
	for i := 0; i < numTransactions; i += batchSize {
		wg.Add(1)
		go func(startIndex int) {
			defer wg.Done()
			for j := startIndex; j < startIndex+batchSize && j < numTransactions; j++ {
				// Simulate creating a transaction
				txID := fmt.Sprintf("tx%d", j)
				inputs := []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}}
				outputs := []shared.UTXO{{TransactionID: txID, Index: 0, OwnerAddress: "Bob", Amount: 100}}

				// Generate AES key for each transaction to simulate encryption process
				aesKey, _ := shared.GenerateAESKey()

				// Simulate transaction encryption (normally you would encrypt something meaningful)
				encryptedData, _ := shared.EncryptWithAES(aesKey, []byte(txID))

				// Decrypt the data to simulate the full transaction lifecycle
				_, _ = shared.DecryptWithAES(aesKey, encryptedData)

				// Serialize the transaction for signing
				txBytes, _ := json.Marshal(shared.Transaction{ID: txID, Inputs: inputs, Outputs: outputs, Timestamp: time.Now().Unix()})

				// Sign the serialized transaction data with both Ed25519
				edSignature := ed25519.Sign(edPrivateKey, txBytes)

				// Verify both signatures
				if !ed25519.Verify(edPublicKey, txBytes, edSignature) {
					t.Errorf("Ed25519 signature verification failed at transaction %d", j)
				}
			}
		}(i)
	}

	wg.Wait()

	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()

	t.Logf("Processed %d dual-signed and AES-256 encrypted transactions in %s. TPS: %f", numTransactions, elapsed, tps)
}

// go test -v -timeout 30s -run ^TestBlockTime$ github.com/thrylos-labs/thrylos/core

func TestBlockTime(t *testing.T) {
	// Generate Ed25519 keys
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Ed25519 key pair: %v", err)
	}

	// Define the number of transactions and number of transactions per block
	numTransactions := 1000
	transactionsPerBlock := 100 // Assuming 100 transactions per block

	var wg sync.WaitGroup
	var blockFinalizeTimes []time.Duration

	start := time.Now()

	// Process transactions and group them into blocks
	for i := 0; i < numTransactions; i += transactionsPerBlock {
		wg.Add(1)
		go func(startIndex int) {
			defer wg.Done()
			blockStartTime := time.Now()

			var blockTransactions []shared.Transaction
			for j := startIndex; j < startIndex+transactionsPerBlock && j < numTransactions; j++ {
				// Create a transaction
				txID := fmt.Sprintf("tx%d", j)
				inputs := []shared.UTXO{{TransactionID: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}}
				outputs := []shared.UTXO{{TransactionID: txID, Index: 0, OwnerAddress: "Bob", Amount: 100}}
				tx := shared.Transaction{ID: txID, Inputs: inputs, Outputs: outputs, Timestamp: time.Now().Unix()}

				// Serialize and sign the transaction
				txBytes, err := json.Marshal(tx)
				if err != nil {
					t.Errorf("Error marshaling transaction %d: %v", j, err)
					continue
				}
				edSignature := ed25519.Sign(edPrivateKey, txBytes)

				// Verify signature and add transaction to block
				if ed25519.Verify(edPublicKey, txBytes, edSignature) {
					blockTransactions = append(blockTransactions, tx)
				} else {
					t.Errorf("Signature verification failed at transaction %d", j)
				}
			}

			// Simulate finalizing the block
			time.Sleep(time.Millisecond * 500) // Simulate delay for block finalization
			blockEndTime := time.Now()
			blockFinalizeTimes = append(blockFinalizeTimes, blockEndTime.Sub(blockStartTime))
		}(i)

	}

	wg.Wait()

	// Calculate average block time
	var totalBlockTime time.Duration
	for _, bt := range blockFinalizeTimes {
		totalBlockTime += bt
	}
	averageBlockTime := totalBlockTime / time.Duration(len(blockFinalizeTimes))

	// Logging the result
	t.Logf("Average block time: %s", averageBlockTime)

	elapsedOverall := time.Since(start)
	t.Logf("Processed %d transactions into blocks with average block time of %s. Total elapsed time: %s", numTransactions, averageBlockTime, elapsedOverall)
}

// go test -v -timeout 30s -run ^TestTransactionThroughputWithGRPC$ github.com/thrylos-labs/thrylos/core

func TestTransactionThroughputWithGRPC(t *testing.T) {
	const (
		numTransactions = 1000
		batchSize       = 10
		grpcAddress     = "localhost:50051"
	)

	// Setup gRPC client
	kacp := keepalive.ClientParameters{
		Time:                10 * time.Second,
		Timeout:             time.Second,
		PermitWithoutStream: true,
	}
	conn, err := grpc.Dial(grpcAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithKeepaliveParams(kacp))
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()
	client := pb.NewBlockchainServiceClient(conn)

	// Generate Ed25519 keys
	_, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Ed25519 key pair: %v", err)
	}

	// Example transaction elements
	inputs := []shared.UTXO{{TransactionID: "input-tx-id", Index: 0, OwnerAddress: "Alice", Amount: 100}}
	outputs := []shared.UTXO{{TransactionID: "output-tx-id", Index: 0, OwnerAddress: "Bob", Amount: 100}}
	aesKey, _ := shared.GenerateAESKey() // Assume this function exists and generates a key for encryption

	start := time.Now()
	var wg sync.WaitGroup

	// Process transactions in batches
	for i := 0; i < numTransactions; i += batchSize {
		wg.Add(1)
		go func(startIndex int) {
			defer wg.Done()
			for j := startIndex; j < startIndex+batchSize && j < numTransactions; j++ {
				txID := fmt.Sprintf("tx%d", j)
				internalTx, err := shared.CreateAndSignTransaction(txID, "Alice", inputs, outputs, edPrivateKey, aesKey)
				if err != nil {
					t.Errorf("Failed to create or sign transaction: %v", err)
					continue
				}
				protoTx := ConvertSharedTransactionToProto(internalTx)

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := client.SubmitTransaction(ctx, &pb.TransactionRequest{Transaction: protoTx}); err != nil {
					st, _ := status.FromError(err)
					t.Errorf("Failed to submit transaction: %v, gRPC status: %v", err, st.Message())
				}
			}

		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()
	t.Logf("Processed %d transactions via gRPC in %s. TPS: %f", numTransactions, elapsed, tps)
}
