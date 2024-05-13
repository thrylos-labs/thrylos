package core

import (
	"context"
	"fmt"
	"log"
	"sync"
	"testing"
	"time"

	pb "github.com/thrylos-labs/thrylos" // ensure this import path is correct

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

func submitTransactionBatch(client pb.BlockchainServiceClient, transactions []*pb.Transaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	batch := &pb.TransactionBatchRequest{
		Transactions: transactions,
	}
	_, err := client.SubmitTransactionBatch(ctx, batch)
	return err
}

// go test -v -timeout 30s -run ^TestBlockTimeWithGRPCDistributed$ github.com/thrylos-labs/thrylos/core

func TestBlockTimeWithGRPCDistributed(t *testing.T) {
	// Establish gRPC connections to remote nodes
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()
	client := pb.NewBlockchainServiceClient(conn)

	// Define the number of transactions and transactions per block
	numTransactions := 1000
	transactionsPerBlock := 100

	var wg sync.WaitGroup
	var blockFinalizeTimes []time.Duration
	start := time.Now()

	// Process transactions and group them into blocks
	for i := 0; i < numTransactions; i += transactionsPerBlock {
		wg.Add(1)
		go func(startIndex int) {
			defer wg.Done()
			blockStartTime := time.Now()

			var blockTransactions []*pb.Transaction
			for j := startIndex; j < startIndex+transactionsPerBlock && j < numTransactions; j++ {
				// Create a transaction
				tx := &pb.Transaction{
					Id:        fmt.Sprintf("tx%d", j),
					Inputs:    []*pb.UTXO{{TransactionId: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
					Outputs:   []*pb.UTXO{{TransactionId: fmt.Sprintf("tx%d", j), Index: 0, OwnerAddress: "Bob", Amount: 100}},
					Timestamp: time.Now().Unix(),
				}

				// Add transaction to block
				blockTransactions = append(blockTransactions, tx)
			}

			// Submit the transaction batch
			err := submitTransactionBatch(client, blockTransactions)
			if err != nil {
				t.Errorf("Error submitting transaction batch: %v", err)
			}

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
