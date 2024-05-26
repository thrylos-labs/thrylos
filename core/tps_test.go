package core

import (
	"context"
	"fmt"
	"log"
	"sync"
	"testing"
	"time"

	pb "github.com/thrylos-labs/thrylos" // ensure this import path is correct
	thrylos "github.com/thrylos-labs/thrylos"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type mockBlockchainServer struct {
	pb.UnimplementedBlockchainServiceServer
}

// Add this method to handle batch submissions
func (s *mockBlockchainServer) SubmitTransactionBatch(ctx context.Context, req *pb.TransactionBatchRequest) (*pb.TransactionBatchResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	// Simulate processing of transactions
	for _, tx := range req.Transactions {
		fmt.Printf("Processed transaction %s\n", tx.Id)
	}
	// Respond that all transactions were processed successfully
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

	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()
	client := thrylos.NewBlockchainServiceClient(conn)

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
