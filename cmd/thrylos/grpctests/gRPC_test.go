package main

import (
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func init() {
	// Initialize the listener for the in-memory connection
	lis = bufconn.Listen(bufSize)
}

// func bufDialer(ctx context.Context, s string) (net.Conn, error) {
// 	return lis.Dial()
// }

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

// type mockBlockchainServer struct {
// 	pb.UnimplementedBlockchainServiceServer
// }

// func (s *mockBlockchainServer) SubmitTransaction(ctx context.Context, req *pb.TransactionRequest) (*pb.TransactionResponse, error) {
// 	return &pb.TransactionResponse{Status: "Transaction added successfully"}, nil
// }

// // // go test -v -timeout 30s -run ^TestBlockTimeWithGRPC$ github.com/thrylos-labs/thrylos/cmd/thrylosnode

// func TestBlockTimeWithGRPC(t *testing.T) {
// 	server := startMockServer()
// 	defer server.Stop()

// 	conn, err := grpc.Dial(":0", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(bufDialer))
// 	if err != nil {
// 		t.Fatalf("Failed to dial server: %v", err)
// 	}
// 	defer conn.Close()

// 	client := pb.NewBlockchainServiceClient(conn)
// 	numTransactions := 1000
// 	transactionsPerBlock := 10
// 	var wg sync.WaitGroup
// 	var mu sync.Mutex
// 	var blockFinalizeTimes []time.Duration

// 	start := time.Now()

// 	for i := 0; i < numTransactions; i += transactionsPerBlock {
// 		wg.Add(1)
// 		go func(startIndex int) {
// 			defer wg.Done()
// 			blockStartTime := time.Now()

// 			blockTransactions := simulateTransactionBatch(startIndex, transactionsPerBlock)
// 			if err := submitTransactions(client, blockTransactions); err != nil {
// 				t.Errorf("Error submitting block starting at transaction %d: %v", startIndex, err)
// 				return
// 			}

// 			blockEndTime := time.Now()
// 			mu.Lock()
// 			blockFinalizeTimes = append(blockFinalizeTimes, blockEndTime.Sub(blockStartTime))
// 			mu.Unlock()
// 		}(i)
// 	}

// 	wg.Wait()

// 	totalBlockTime := time.Duration(0)
// 	for _, bt := range blockFinalizeTimes {
// 		totalBlockTime += bt
// 	}
// 	averageBlockTime := totalBlockTime / time.Duration(len(blockFinalizeTimes))

// 	elapsedOverall := time.Since(start)
// 	t.Logf("Processed %d transactions into blocks with average block time of %s. Total elapsed time: %s", numTransactions, averageBlockTime, elapsedOverall)
// }

// func submitTransactions(client pb.BlockchainServiceClient, transactions []*pb.Transaction) error {
// 	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
// 	defer cancel()
// 	for _, tx := range transactions {
// 		if _, err := client.SubmitTransaction(ctx, &pb.TransactionRequest{Transaction: tx}); err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// // // go test -v -timeout 30s -run ^TestRealisticBlockTimeWithGRPC github.com/thrylos-labs/thrylos/cmd/thrylosnode

// func simulateTransactionBatch(startIndex, batchSize int) []*pb.Transaction {
// 	var transactions []*pb.Transaction
// 	for i := startIndex; i < startIndex+batchSize && i < 1000; i++ {
// 		txID := fmt.Sprintf("tx%d", i)
// 		transaction := &pb.Transaction{
// 			Id:        txID,
// 			Timestamp: time.Now().Unix(),
// 			// Populate Inputs and Outputs as per transaction requirements
// 			Inputs:  []*pb.UTXO{{TransactionId: "prev-tx-id", Index: 0, OwnerAddress: "Alice", Amount: 100}},
// 			Outputs: []*pb.UTXO{{TransactionId: txID, Index: 0, OwnerAddress: "Bob", Amount: 100}},
// 		}
// 		transactions = append(transactions, transaction)
// 	}
// 	return transactions
// }

// func TestSubmitTransaction(t *testing.T) {
// 	server := startMockServer()
// 	defer server.Stop()

// 	// Set up the client connection to the server
// 	ctx := context.Background()
// 	conn, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
// 	if err != nil {
// 		log.Fatalf("Failed to dial: %v", err)
// 	}
// 	defer conn.Close()

// 	client := pb.NewBlockchainServiceClient(conn)

// 	// Prepare and send the request
// 	transaction := &pb.Transaction{
// 		Id:        "transaction-id",
// 		Timestamp: time.Now().Unix(),
// 		Inputs: []*pb.UTXO{
// 			{
// 				TransactionId: "prev-tx-id",
// 				Index:         0,
// 				OwnerAddress:  "owner-address-example",
// 				Amount:        50,
// 			},
// 		},
// 		Outputs: []*pb.UTXO{
// 			{
// 				TransactionId: "new-tx-id",
// 				Index:         0,
// 				OwnerAddress:  "recipient-address-example",
// 				Amount:        50,
// 			},
// 		},
// 		Signature: []byte("transaction-signature"),
// 		Sender:    "sender-address",
// 	}
// 	r, err := client.SubmitTransaction(ctx, &pb.TransactionRequest{Transaction: transaction})
// 	assert.NoError(t, err)
// 	assert.NotNil(t, r)
// 	assert.Equal(t, "Transaction added successfully", r.Status)
// }
