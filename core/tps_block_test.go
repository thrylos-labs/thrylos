package core

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	pb "github.com/thrylos-labs/thrylos" // ensure this import path is correct

	// ensure this import path is correct

	"github.com/thrylos-labs/thrylos/shared"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
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

func randomDelay(maxDelay int) time.Duration {
	nanoTime := time.Now().UnixNano()
	return time.Duration(nanoTime % int64(maxDelay))
}

func TestBlockTime(t *testing.T) {
	// Generate Ed25519 keys
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Error generating Ed25519 key pair: %v", err)
	}

	// Define the number of transactions and number of transactions per block
	numTransactions := 1000
	transactionsPerBlock := 100

	var wg sync.WaitGroup
	var mu sync.Mutex
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
				// Simulate network delay
				time.Sleep(randomDelay(10) * time.Millisecond)

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

			// Simulate consensus delay
			time.Sleep(randomDelay(20)*time.Millisecond + 50*time.Millisecond) // Variable delay for block finalization
			blockEndTime := time.Now()

			mu.Lock()
			blockFinalizeTimes = append(blockFinalizeTimes, blockEndTime.Sub(blockStartTime))
			mu.Unlock()
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

// func startMockServer() *grpc.Server {
// 	server := grpc.NewServer()
// 	pb.RegisterBlockchainServiceServer(server, &mockBlockchainServer{})
// 	go func() {
// 		if err := server.Serve(lis); err != nil {
// 			log.Fatalf("Server exited with error: %v", err)
// 		}
// 	}()
// 	return server
// }

const bufSize = 1024 * 1024

// type mockBlockchainServer struct {
// 	pb.UnimplementedBlockchainServiceServer
// }

func bufDialer(ctx context.Context, s string) (net.Conn, error) {
	return lis.Dial()
}

var lis *bufconn.Listener

func init() {
	// Initialize the listener for the in-memory connection
	lis = bufconn.Listen(bufSize)
}

func TestTransactionThroughputWithGRPC(t *testing.T) {
	const (
		numTransactions = 1000
		batchSize       = 10
	)

	// Start a local gRPC server
	server := startMockServer() // This function needs to correctly start the server
	defer server.Stop()

	conn, err := grpc.Dial("bufnet", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()
	client := pb.NewBlockchainServiceClient(conn)

	start := time.Now()
	var wg sync.WaitGroup

	// Process transactions in batches
	for i := 0; i < numTransactions; i += batchSize {
		wg.Add(1)
		go func(startIndex int) {
			defer wg.Done()
			transactions := make([]*pb.Transaction, batchSize)
			for j := 0; j < batchSize && startIndex+j < numTransactions; j++ {
				txID := fmt.Sprintf("tx%d", startIndex+j)
				transactions[j] = &pb.Transaction{
					Id: txID,
					// Assume other necessary fields are populated here
				}
			}

			batchRequest := &pb.TransactionBatchRequest{Transactions: transactions}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := client.SubmitTransactionBatch(ctx, batchRequest)
			if err != nil {
				t.Errorf("Failed to submit transaction batch starting at index %d: %v", startIndex, err)
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()
	t.Logf("Processed %d transactions via gRPC in %s. TPS: %f", numTransactions, elapsed, tps)
}
