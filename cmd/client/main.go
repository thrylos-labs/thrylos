package main

import (
	"context"
	"log"
	"sync"
	"time"

	pb "github.com/thrylos-labs/thrylos" // ensure this import path is correct
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials" // Import for TLS credentials
	"google.golang.org/grpc/keepalive"
)

func main() {
	var kacp = keepalive.ClientParameters{
		Time:                10 * time.Second, // Send keepalive pings every 10 seconds if there is no activity
		Timeout:             time.Second,      // Wait 1 second for ping ack before considering the connection dead
		PermitWithoutStream: true,             // Send pings even without active streams
	}

	// Load TLS credentials from file
	creds, err := credentials.NewClientTLSFromFile("../localhost.crt", "localhost")
	if err != nil {
		log.Fatalf("could not load TLS cert: %s", err)
	}

	// Connect to the gRPC server with keepalive and TLS parameters
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds),
		grpc.WithBlock(),
		grpc.WithKeepaliveParams(kacp),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024*10))) // 10 MB
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	c := pb.NewBlockchainServiceClient(conn) // Use the correct client constructor from generated protobuf code

	// Example transaction batch processing
	transactions := []*pb.Transaction{
		{Id: "tx1", Timestamp: time.Now().Unix()}, // Add more details as necessary
		{Id: "tx2", Timestamp: time.Now().Unix()},
	}
	err = submitTransactionBatch(c, transactions)
	if err != nil {
		log.Fatalf("Could not submit transaction batch: %v", err)
	}
}

// This function sends transactions asynchronously and uses a WaitGroup to wait for all transactions to be processed, which can be particularly effective in a high-concurrency environment.

func submitTransactionsAsync(client pb.BlockchainServiceClient, transactions []*pb.Transaction) {
	var wg sync.WaitGroup
	wg.Add(len(transactions))

	for _, tx := range transactions {
		go func(tx *pb.Transaction) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := client.SubmitTransaction(ctx, &pb.TransactionRequest{Transaction: tx})
			if err != nil {
				log.Printf("Failed to submit transaction %v: %v", tx.Id, err)
				// Handle error, e.g., retry or log
			}
		}(tx)
	}

	wg.Wait() // Wait for all transactions to be submitted
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

// Client Setup:
// Initialize keepalive parameters for maintaining a gRPC connection.
// Connect to the gRPC server using these parameters.
// Create a blockchain service client using the connected gRPC channel.
// Transaction Creation and Submission:
// Build a transaction with inputs and outputs as per the UTXO model.
// Send the transaction through the gRPC client, handle errors, and log the transaction status.
// Asynchronous Transaction Submission:
// Submit multiple transactions asynchronously, using goroutines and a wait group to manage concurrency.
