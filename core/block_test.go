package core

// ensure this import path is correct

// func startMockServerNew() *grpc.Server {
// 	server := grpc.NewServer()
// 	pb.RegisterBlockchainServiceServer(server, &mockBlockchainServer{})
// 	lis, err := net.Listen("tcp", "localhost:50051") // Ensuring it listens correctly
// 	if err != nil {
// 		log.Fatalf("Failed to listen: %v", err)
// 	}
// 	go func() {
// 		if err := server.Serve(lis); err != nil {
// 			log.Fatalf("Server exited with error: %v", err)
// 		}
// 	}()
// 	return server
// }

// type mockBlockchainServerNew struct {
// 	pb.UnimplementedBlockchainServiceServer
// }

// func (s *mockBlockchainServerNew) SubmitTransactionBatch(ctx context.Context, req *pb.TransactionBatchRequest) (*pb.TransactionBatchResponse, error) {
// 	if req == nil {
// 		return nil, fmt.Errorf("request cannot be nil")
// 	}
// 	for _, tx := range req.Transactions {
// 		fmt.Printf("Processed transaction %s\n", tx.Id)
// 	}
// 	return &pb.TransactionBatchResponse{
// 		Status: "All transactions processed successfully",
// 	}, nil
// }

// func TestBlockTimeWithGRPCDistributed(t *testing.T) {
// 	server := startMockServer()
// 	defer server.Stop()

// 	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
// 	if err != nil {
// 		t.Fatalf("Failed to connect to gRPC server: %v", err)
// 	}
// 	defer conn.Close()

// 	client := pb.NewBlockchainServiceClient(conn)

// 	// Define the number of transactions and transactions per block
// 	numTransactions := 1000
// 	transactionsPerBlock := 100

// 	var wg sync.WaitGroup
// 	var mu sync.Mutex // Mutex to protect slice access in concurrent goroutines
// 	var blockFinalizeTimes []time.Duration
// 	start := time.Now()

// 	// Process transactions and group them into blocks
// 	for i := 0; i < numTransactions; i += transactionsPerBlock {
// 		wg.Add(1)
// 		go func(startIndex int) {
// 			defer wg.Done()
// 			blockStartTime := time.Now()

// 			var blockTransactions []*pb.Transaction
// 			for j := startIndex; j < startIndex+transactionsPerBlock && j < numTransactions; j++ {
// 				tx := &pb.Transaction{
// 					Id:        fmt.Sprintf("tx%d", j),
// 					Inputs:    []*pb.UTXO{{TransactionId: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
// 					Outputs:   []*pb.UTXO{{TransactionId: fmt.Sprintf("tx%d", j), Index: 0, OwnerAddress: "Bob", Amount: 100}},
// 					Timestamp: time.Now().Unix(),
// 				}
// 				blockTransactions = append(blockTransactions, tx)
// 			}

// 			if err := submitTransactionBatchBlock(client, blockTransactions); err != nil {
// 				t.Errorf("Error submitting transaction batch: %v", err)
// 			}

// 			blockEndTime := time.Now()
// 			mu.Lock()
// 			blockFinalizeTimes = append(blockFinalizeTimes, blockEndTime.Sub(blockStartTime))
// 			mu.Unlock()
// 		}(i)
// 	}

// 	wg.Wait()

// 	var totalBlockTime time.Duration
// 	for _, bt := range blockFinalizeTimes {
// 		totalBlockTime += bt
// 	}
// 	averageBlockTime := totalBlockTime / time.Duration(len(blockFinalizeTimes))

// 	elapsedOverall := time.Since(start)
// 	t.Logf("Processed %d transactions into blocks with average block time of %s. Total elapsed time: %s", numTransactions, averageBlockTime, elapsedOverall)
// }

// func submitTransactionBatchBlock(client pb.BlockchainServiceClient, transactions []*pb.Transaction) error {
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()

// 	batch := &pb.TransactionBatchRequest{
// 		Transactions: transactions,
// 	}
// 	_, err := client.SubmitTransactionBatch(ctx, batch)
// 	return err
// }

// func startMockServerBlock() *grpc.Server {
// 	server := grpc.NewServer()
// 	pb.RegisterBlockchainServiceServer(server, &mockBlockchainServer{})
// 	lis, err := net.Listen("tcp", "localhost:50051") // Ensure the server is listening on the correct address
// 	if err != nil {
// 		log.Fatalf("Failed to listen: %v", err)
// 	}
// 	go func() {
// 		if err := server.Serve(lis); err != nil {
// 			log.Fatalf("Server exited with error: %v", err)
// 		}
// 	}()
// 	return server
// }

// type mockBlockchainServerBlock struct {
// 	pb.UnimplementedBlockchainServiceServer
// }

// func (s *mockBlockchainServer) SubmitTransactionBatchBlock(ctx context.Context, req *pb.TransactionBatchRequest) (*pb.TransactionBatchResponse, error) {
// 	if req == nil {
// 		return nil, fmt.Errorf("request cannot be nil")
// 	}
// 	// Simulate processing of transactions
// 	for _, tx := range req.Transactions {
// 		fmt.Printf("Processed transaction %s\n", tx.Id)
// 	}
// 	return &pb.TransactionBatchResponse{
// 		Status: "All transactions processed successfully",
// 	}, nil
// }
