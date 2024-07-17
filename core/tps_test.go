package core

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/thrylos-labs/thrylos" // ensure this import path is correct
	thrylos "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

type mockBlockchainServer struct {
	pb.UnimplementedBlockchainServiceServer
}

func (s *mockBlockchainServer) ValidateTransaction(tx *pb.Transaction) bool {
	// Example simple validation: check if transaction ID is not empty
	return tx.Id != ""
}

// Add this method to handle batch submissions
func (s *mockBlockchainServer) SubmitTransactionBatch(ctx context.Context, req *pb.TransactionBatchRequest) (*pb.TransactionBatchResponse, error) {
	start := time.Now()
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	var wg sync.WaitGroup
	for _, tx := range req.Transactions {
		go func(tx *pb.Transaction) {
			if !s.ValidateTransaction(tx) {
				fmt.Printf("Invalid transaction %s\n", tx.Id)
				return
			}
			fmt.Printf("Processed transaction %s\n", tx.Id)
			// Reduce or conditionally apply sleep here if necessary
		}(tx)
	}

	wg.Wait()
	elapsed := time.Since(start)
	fmt.Printf("Processed batch in %s\n", elapsed)
	return &pb.TransactionBatchResponse{
		Status: "All transactions processed successfully",
	}, nil
}

func startMockServer() *grpc.Server {
	server := grpc.NewServer()
	pb.RegisterBlockchainServiceServer(server, &mockBlockchainServer{})
	go func() {
		if err := server.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()
	return server
}

func TestConvertUTXOsToRequiredFormat(t *testing.T) {
	loadEnvTest() // Load environment variables

	os.Setenv("GENESIS_ACCOUNT", "dummy_genesis_account_value") // Set a dummy GENESIS_ACCOUNT
	defer os.Unsetenv("GENESIS_ACCOUNT")

	tempDir, err := ioutil.TempDir("", "blockchain_test") // Create a temporary directory
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	aesKey, err := shared.GenerateAESKey() // Generate an AES key
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	firebaseApp := initializeFirebaseApp() // Initialize Firebase app
	genesisAccount := os.Getenv("GENESIS_ACCOUNT")

	bc, err := NewBlockchain(tempDir, aesKey, genesisAccount, firebaseApp) // Initialize the blockchain
	if err != nil {
		t.Fatalf("Failed to initialize blockchain: %v", err)
	}

	// Add some test UTXOs to the blockchain for conversion
	bc.UTXOs["key1"] = []*thrylos.UTXO{
		{TransactionId: "tx1", Index: 1, OwnerAddress: "addr1", Amount: 100},
		{TransactionId: "tx2", Index: 2, OwnerAddress: "addr2", Amount: 200},
	}

	convertedUTXOs := bc.convertUTXOsToRequiredFormat()

	// Assertions to verify the correctness of the conversion
	if len(convertedUTXOs) != len(bc.UTXOs) {
		t.Errorf("Expected %d keys in converted UTXOs, got %d", len(bc.UTXOs), len(convertedUTXOs))
	}

	for key, utxos := range convertedUTXOs {
		if len(utxos) != len(bc.UTXOs[key]) {
			t.Errorf("Mismatch in number of UTXOs for key %s: expected %d, got %d", key, len(bc.UTXOs[key]), len(utxos))
		}
		for i, utxo := range utxos {
			if utxo.TransactionID != bc.UTXOs[key][i].TransactionId ||
				utxo.Amount != bc.UTXOs[key][i].Amount ||
				utxo.OwnerAddress != bc.UTXOs[key][i].OwnerAddress ||
				utxo.Index != int(bc.UTXOs[key][i].Index) {
				t.Errorf("Mismatch in UTXO details at index %d for key %s", i, key)
			}
		}
	}
}

func TestConvertToSharedTransaction(t *testing.T) {
	loadEnvTest() // Load environment variables

	os.Setenv("GENESIS_ACCOUNT", "dummy_genesis_account_value") // Set a dummy GENESIS_ACCOUNT
	defer os.Unsetenv("GENESIS_ACCOUNT")

	tempDir, err := ioutil.TempDir("", "blockchain_test") // Create a temporary directory
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	aesKey, err := shared.GenerateAESKey() // Generate an AES key
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	firebaseApp := initializeFirebaseApp() // Initialize Firebase app
	genesisAccount := os.Getenv("GENESIS_ACCOUNT")

	bc, err := NewBlockchain(tempDir, aesKey, genesisAccount, firebaseApp) // Initialize the blockchain
	if err != nil {
		t.Fatalf("Failed to initialize blockchain: %v", err)
	}
	// Mock a thrylos.Transaction with expected values
	tx := &thrylos.Transaction{
		Id:      "test123",
		Inputs:  []*thrylos.UTXO{{TransactionId: "tx1", Index: 1, OwnerAddress: "addr1", Amount: 100}},
		Outputs: []*thrylos.UTXO{{TransactionId: "tx1", Index: 0, OwnerAddress: "addr2", Amount: 50}},
	}

	// Convert and check results
	convertedTx, err := bc.convertToSharedTransaction(tx)
	if err != nil {
		t.Errorf("Failed to convert transaction: %v", err)
	}
	if convertedTx.ID != tx.Id {
		t.Errorf("Transaction ID mismatch: got %v, want %v", convertedTx.ID, tx.Id)
	}
	// Add more checks for other fields
}

// TestValidateTransactionsConcurrently tests the concurrent transaction validation

func TestValidateTransactionsConcurrently(t *testing.T) {
	loadEnvTest() // Load environment variables

	os.Setenv("GENESIS_ACCOUNT", "dummy_genesis_account_value") // Set a dummy GENESIS_ACCOUNT
	defer os.Unsetenv("GENESIS_ACCOUNT")

	tempDir, err := ioutil.TempDir("", "blockchain_test") // Create a temporary directory
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	aesKey, err := shared.GenerateAESKey() // Generate an AES key
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	firebaseApp := initializeFirebaseApp() // Initialize Firebase app
	genesisAccount := os.Getenv("GENESIS_ACCOUNT")

	bc, err := NewBlockchain(tempDir, aesKey, genesisAccount, firebaseApp) // Initialize the blockchain
	if err != nil {
		t.Fatalf("Failed to initialize blockchain: %v", err)
	}

	// Create a set of mock transactions
	transactions := make([]*thrylos.Transaction, 5)
	for i := range transactions {
		if i%2 == 0 {
			transactions[i] = &thrylos.Transaction{Id: fmt.Sprintf("tx%d", i)}
		} else {
			transactions[i] = &thrylos.Transaction{Id: ""} // Deliberately invalid to trigger error
		}
	}

	// Validate transactions concurrently
	startTime := time.Now()
	errors := bc.validateTransactionsConcurrently(transactions)
	duration := time.Since(startTime)

	// Check the results
	expectedErrors := 2 // Expecting 2 errors based on the test setup
	if len(errors) != expectedErrors {
		t.Errorf("Expected %d errors, got %d", expectedErrors, len(errors))
	}

	for _, err := range errors {
		t.Log("Validation error:", err)
	}

	t.Logf("Validation completed in %v", duration)
}

// go test -v -timeout 30s -run ^TestTransactionThroughputWithGRPCUpdated$ github.com/thrylos-labs/thrylos/core

// Adjust the TestTransactionThroughputWithGRPC to use the correct dialing address
func TestTransactionThroughputWithGRPCUpdated(t *testing.T) {
	const (
		numTransactions = 10000 // Increase the total number of transactions
		batchSize       = 100   // Increase batch size
		numGoroutines   = 100   // Number of concurrent goroutines
	)

	server := startMockServer()
	defer server.Stop()

	conn, err := grpc.Dial("localhost:50051", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()
	client := pb.NewBlockchainServiceClient(conn)

	start := time.Now()
	var wg sync.WaitGroup

	transactionsPerGoroutine := numTransactions / numGoroutines

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineIndex int) {
			defer wg.Done()
			for i := 0; i < transactionsPerGoroutine; i += batchSize {
				transactions := make([]*pb.Transaction, batchSize)
				for j := 0; j < batchSize && goroutineIndex*transactionsPerGoroutine+i+j < numTransactions; j++ {
					txID := fmt.Sprintf("tx%d", goroutineIndex*transactionsPerGoroutine+i+j)
					transactions[j] = &pb.Transaction{Id: txID}
				}
				batchRequest := &pb.TransactionBatchRequest{Transactions: transactions}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, err := client.SubmitTransactionBatch(ctx, batchRequest)
				if err != nil {
					t.Errorf("Failed to submit transaction batch: %v", err)
				}
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()
	t.Logf("Processed %d transactions via gRPC in %s. TPS: %f", numTransactions, elapsed, tps)
}

// go test -v -timeout 30s -run ^TestBlockTimeWithGRPCDistributed$ github.com/thrylos-labs/thrylos/core

// go test -v -timeout 30s -run ^TestTransactionCosts$ github.com/thrylos-labs/thrylos/core

func TestTransactionCosts(t *testing.T) {
	const (
		smallDataSize  = 10    // 10 bytes
		mediumDataSize = 1000  // 1000 bytes
		largeDataSize  = 10000 // 10 KB
	)

	conn, err := grpc.Dial("localhost:50051", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()
	client := pb.NewBlockchainServiceClient(conn)

	testCases := []struct {
		name        string
		dataSize    int
		expectedGas int
	}{
		{"SmallData", smallDataSize, CalculateGas(smallDataSize)},
		{"MediumData", mediumDataSize, CalculateGas(mediumDataSize)},
		{"LargeData", largeDataSize, CalculateGas(largeDataSize)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.dataSize)
			transaction := &thrylos.Transaction{
				Id:        fmt.Sprintf("%s-transaction", tc.name),
				Timestamp: time.Now().Unix(),
				// Assuming encrypted data is representative of actual transaction data
				EncryptedInputs:  data,
				EncryptedOutputs: data,
				Signature:        []byte("dummy-signature"),
				Sender:           "test-sender",
			}

			request := &thrylos.TransactionRequest{Transaction: transaction}
			_, err := client.SubmitTransaction(context.Background(), request)
			if err != nil {
				t.Errorf("Failed to submit transaction: %v", err)
			}

			// Log the expected gas cost for the transaction
			t.Logf("Transaction %s expected to cost %d gas units", tc.name, tc.expectedGas)

			// Optionally, validate that the gas cost matches expected values
			// This might involve querying a mock or actual database, or adjusting the test setup to capture this data.
		})
	}
}

// go test -v -timeout 30s -run ^TestBlockTimeWithGRPC$ github.com/thrylos-labs/thrylos/core

func TestBlockTimeWithGRPC(t *testing.T) {
	const (
		numTransactions = 1000 // Total number of transactions to simulate
		blockSize       = 100  // Number of transactions per block
		numBlocks       = numTransactions / blockSize
	)

	server := startMockServer()
	defer server.Stop()

	conn, err := grpc.Dial("localhost:50051", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := pb.NewBlockchainServiceClient(conn)

	// Simulate block formation
	var wg sync.WaitGroup
	start := time.Now()

	for b := 0; b < numBlocks; b++ {
		wg.Add(1)
		go func(blockIndex int) {
			defer wg.Done()
			transactions := make([]*pb.Transaction, blockSize)
			for j := 0; j < blockSize; j++ {
				txID := fmt.Sprintf("tx%d", blockIndex*blockSize+j)
				transactions[j] = &pb.Transaction{Id: txID}
			}
			batchRequest := &pb.TransactionBatchRequest{Transactions: transactions}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := client.SubmitTransactionBatch(ctx, batchRequest)
			if err != nil {
				t.Errorf("Failed to submit transaction batch: %v", err)
			}
			// Simulate consensus delay
			time.Sleep(50 * time.Millisecond) // Simulate a fixed delay for block consensus
		}(b)
	}

	wg.Wait()
	elapsed := time.Since(start)
	blockTime := elapsed / time.Duration(numBlocks)
	t.Logf("Processed %d blocks via gRPC in %s. Average block time: %s", numBlocks, elapsed, blockTime)
}

// without Grpc

// go test -v -timeout 30s -run ^TestRealisticBlockTimeWithGRPC$ github.com/thrylos-labs/thrylos/core

func TestRealisticBlockTimeWithGRPC(t *testing.T) {
	const (
		numTransactions            = 1000 // Total number of transactions to simulate
		blockSize                  = 100  // Number of transactions per block
		numBlocks                  = numTransactions / blockSize
		averageNetworkLatency      = 100 * time.Millisecond
		averageBlockValidationTime = 300 * time.Millisecond
		averageTransactionTime     = 10 * time.Millisecond
	)

	var mu sync.Mutex // Declare a mutex to synchronize access to blockFinalizeTimes

	server := startMockServer() // Ensure this function correctly initializes and starts your gRPC server
	defer server.Stop()

	conn, err := grpc.Dial("localhost:50051", grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := pb.NewBlockchainServiceClient(conn)

	var wg sync.WaitGroup
	var blockFinalizeTimes []time.Duration

	start := time.Now()

	for b := 0; b < numBlocks; b++ {
		wg.Add(1)
		go func(blockIndex int) {
			defer wg.Done()
			blockStartTime := time.Now()

			transactions := make([]*pb.Transaction, blockSize)
			for j := 0; j < blockSize; j++ {
				txID := fmt.Sprintf("tx%d", blockIndex*blockSize+j)
				transactions[j] = &pb.Transaction{Id: txID}
			}
			batchRequest := &pb.TransactionBatchRequest{Transactions: transactions}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Simulate the sending of transactions as a batch
			_, err := client.SubmitTransactionBatch(ctx, batchRequest)
			if err != nil {
				t.Errorf("Failed to submit transaction batch at index %d: %v", blockIndex, err)
				return
			}

			// Simulate transaction processing time per transaction and block validation
			time.Sleep(time.Duration(blockSize)*averageTransactionTime + averageBlockValidationTime + averageNetworkLatency)

			mu.Lock()
			blockFinalizeTimes = append(blockFinalizeTimes, time.Since(blockStartTime))
			mu.Unlock()
		}(b)
	}

	wg.Wait()

	totalBlockTime := time.Duration(0)
	for _, bt := range blockFinalizeTimes {
		totalBlockTime += bt
	}
	averageBlockTime := totalBlockTime / time.Duration(len(blockFinalizeTimes))

	elapsedOverall := time.Since(start)
	t.Logf("Processed %d blocks in %s with average block time: %s", numBlocks, elapsedOverall, averageBlockTime)
}

// go test -v -timeout 30s -run ^TestTransactionThroughputWithoutGRPC$ github.com/thrylos-labs/thrylos/core

func TestTransactionThroughputWithoutGRPC(t *testing.T) {
	const (
		numTransactions = 5000 // You can adjust this down for more detailed profiling per transaction.
		batchSize       = 50   // Smaller batch sizes might simulate real-world transaction bursts better.
		numGoroutines   = 50   // Adjust based on the level of concurrency you want to simulate.
	)

	start := time.Now()
	var wg sync.WaitGroup

	transactionsPerGoroutine := numTransactions / numGoroutines

	processTransactions := func(transactions []*pb.Transaction) error {
		// Simulate processing delay, remove or adjust as needed
		time.Sleep(10 * time.Millisecond)
		return nil
	}

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineIndex int) {
			defer wg.Done()
			for i := 0; i < transactionsPerGoroutine; i += batchSize {
				transactions := make([]*pb.Transaction, 0, batchSize)
				for j := 0; j < batchSize && goroutineIndex*transactionsPerGoroutine+i+j < numTransactions; j++ {
					txID := fmt.Sprintf("tx%d", goroutineIndex*transactionsPerGoroutine+i+j)
					transactions = append(transactions, &pb.Transaction{Id: txID})
				}
				if err := processTransactions(transactions); err != nil {
					t.Errorf("Failed to process transaction batch: %v", err)
				}
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()
	t.Logf("Processed %d transactions locally in %s. TPS: %f", numTransactions, elapsed, tps)
}

// go test -v -timeout 30s -run ^TestTransactionThroughputWithMoreRealism$ github.com/thrylos-labs/thrylos/core

func TestTransactionThroughputWithMoreRealism(t *testing.T) {
	const (
		numTransactions = 10000
		batchSize       = 100
		numGoroutines   = 100
	)

	loadEnvTest() // Load environment variables

	os.Setenv("GENESIS_ACCOUNT", "dummy_genesis_account_value") // Set a dummy GENESIS_ACCOUNT
	defer os.Unsetenv("GENESIS_ACCOUNT")

	tempDir, err := ioutil.TempDir("", "blockchain_test") // Create a temporary directory
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	aesKey, err := shared.GenerateAESKey() // Generate an AES key
	if err != nil {
		t.Fatalf("Failed to generate AES key: %v", err)
	}

	firebaseApp := initializeFirebaseApp() // Initialize Firebase app
	genesisAccount := os.Getenv("GENESIS_ACCOUNT")

	bc, err := NewBlockchain(tempDir, aesKey, genesisAccount, firebaseApp) // Initialize the blockchain
	if err != nil {
		t.Fatalf("Failed to initialize blockchain: %v", err)
	}

	var totalErrorCount int32
	start := time.Now()
	var wg sync.WaitGroup

	processTransactions := func(transactions []*pb.Transaction) error {
		// Simulate realistic network delay
		time.Sleep(20 * time.Millisecond)

		// Convert pb.Transaction to thrylos.Transaction
		thrylosTransactions := make([]*thrylos.Transaction, len(transactions))
		for i, tx := range transactions {
			thrylosTransactions[i] = &thrylos.Transaction{Id: tx.Id}
		}

		// Validate transactions concurrently
		errors := bc.validateTransactionsConcurrently(thrylosTransactions)
		if len(errors) > 0 {
			atomic.AddInt32(&totalErrorCount, int32(len(errors)))
			return fmt.Errorf("validation errors: %v", errors)
		}

		// Simulate realistic database write delay
		time.Sleep(30 * time.Millisecond)

		return nil
	}

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineIndex int) {
			defer wg.Done()
			for i := 0; i < numTransactions/numGoroutines; i += batchSize {
				transactions := make([]*pb.Transaction, 0, batchSize)
				for j := 0; j < batchSize && i+j < numTransactions; j++ {
					txID := fmt.Sprintf("tx%d", i+j)
					transactions = append(transactions, &pb.Transaction{Id: txID})
				}
				if err := processTransactions(transactions); err != nil {
					t.Errorf("Failed to process transaction batch: %v", err)
				}
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()
	avgLatency := elapsed.Seconds() * 1000 / float64(numTransactions) // Average latency in milliseconds
	errorRate := float64(atomic.LoadInt32(&totalErrorCount)) / float64(numTransactions) * 100

	t.Logf("Processed %d transactions in %s. TPS: %f, Avg Latency: %f ms, Error Rate: %.2f%%", numTransactions, elapsed, tps, avgLatency, errorRate)
}

// go test -v -timeout 30s -run ^TestTransactionThroughputWithIncrementalLoad$ github.com/thrylos-labs/thrylos/core

func TestTransactionThroughputWithIncrementalLoad(t *testing.T) {
	testCases := []struct {
		numTransactions int
		batchSize       int
		numGoroutines   int
	}{
		{1000, 50, 10},
		{2000, 100, 20},
		{5000, 250, 50},
		{10000, 500, 100},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d Transactions %d Goroutines", tc.numTransactions, tc.numGoroutines), func(t *testing.T) {
			executeLoadTest(t, tc.numTransactions, tc.batchSize, tc.numGoroutines)
		})
	}
}

func executeLoadTest(t *testing.T, numTransactions, batchSize, numGoroutines int) {
	var totalErrorCount int32
	start := time.Now()
	var wg sync.WaitGroup

	processTransactions := func(transactions []*pb.Transaction) error {
		// Introduce variable delay to simulate network and processing time
		delay := time.Duration(rand.Intn(100)) * time.Millisecond
		time.Sleep(delay)

		// Introduce errors in a controlled manner
		if rand.Float32() < 0.05 { // 5% error rate
			atomic.AddInt32(&totalErrorCount, 1)
			return fmt.Errorf("simulated processing error")
		}

		return nil
	}

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineIndex int) {
			defer wg.Done()
			for i := 0; i < numTransactions/numGoroutines; i += batchSize {
				transactions := make([]*pb.Transaction, 0, batchSize)
				for j := 0; j < batchSize && i+j < numTransactions; j++ {
					txID := fmt.Sprintf("tx%d", i+j)
					transaction := &pb.Transaction{Id: txID}
					// Simulate serialization of transaction data
					data, _ := proto.Marshal(transaction)
					transaction = &pb.Transaction{}
					_ = proto.Unmarshal(data, transaction)
					transactions = append(transactions, transaction)
				}
				if err := processTransactions(transactions); err != nil {
					t.Logf("Error processing transaction batch: %v", err)
				}
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)
	tps := float64(numTransactions) / elapsed.Seconds()
	avgLatency := elapsed.Seconds() * 1000 / float64(numTransactions)
	errorRate := float64(totalErrorCount) / float64(numTransactions) * 100

	t.Logf("Processed %d transactions in %s. TPS: %f, Avg Latency: %f ms, Error Rate: %.2f%%", numTransactions, elapsed, tps, avgLatency, errorRate)
}
