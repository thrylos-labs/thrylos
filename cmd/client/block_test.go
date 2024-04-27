package main // or whatever package main.go is part of

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	// Import this if using the common package approach
	pb "github.com/thrylos-labs/thrylos"
	"google.golang.org/grpc"
)

// go test -v -timeout 30s -run ^TestBlockTimeGRPC$ github.com/thrylos-labs/thrylos/cmd/client/block_test.go

func TestBlockTimeGRPC(t *testing.T) {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		t.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()
	client := pb.NewBlockchainServiceClient(conn)

	// Retrieve the last block index before submitting any transactions to establish a baseline.
	_, initialIndex, err := getLastBlock(client) // Ignoring the block itself
	if err != nil {
		t.Fatalf("Failed to get the initial last block: %v", err)
	}
	t.Logf("Initial last block index: %d", initialIndex)

	numTransactions := 1000
	transactionsPerBlock := 100
	numBlocks := numTransactions / transactionsPerBlock

	var wg sync.WaitGroup
	blockFinalizeTimes := make([]time.Duration, numBlocks)

	start := time.Now()

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(blockIndex int) {
			defer wg.Done()
			blockStartTime := time.Now()

			for j := 0; j < transactionsPerBlock; j++ {
				tx := &pb.Transaction{
					Id:        fmt.Sprintf("tx%d", blockIndex*transactionsPerBlock+j),
					Timestamp: time.Now().Unix(),
				}

				_, err := client.SubmitTransaction(context.Background(), &pb.TransactionRequest{Transaction: tx})
				if err != nil {
					t.Errorf("Failed to submit transaction: %v", err)
					return
				}
			}

			confirmed := waitForBlockConfirmation(client, int32(blockIndex+int(initialIndex)+1))
			if !confirmed {
				t.Errorf("Block %d was not confirmed within the timeout period", blockIndex)
				return
			}

			blockEndTime := time.Now()
			blockFinalizeTimes[blockIndex] = blockEndTime.Sub(blockStartTime)
		}(i)
	}

	wg.Wait()

	totalBlockTime := time.Duration(0)
	for _, bt := range blockFinalizeTimes {
		totalBlockTime += bt
	}
	averageBlockTime := totalBlockTime / time.Duration(numBlocks)

	elapsed := time.Since(start)
	t.Logf("Processed %d transactions into %d blocks in %s. Average block time: %s", numTransactions, numBlocks, elapsed, averageBlockTime)
}
