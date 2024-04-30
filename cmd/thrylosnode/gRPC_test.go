package main

// const bufSize = 1024 * 1024

// var lis *bufconn.Listener

// func init() {
// 	// Initialize the listener for the in-memory connection
// 	lis = bufconn.Listen(bufSize)
// }

// func bufDialer(context.Context, string) (net.Conn, error) {
// 	return lis.Dial()
// }

// func startMockServer() *grpc.Server {
// 	server := grpc.NewServer()
// 	thrylos.RegisterBlockchainServiceServer(server, &mockBlockchainServer{})
// 	go func() {
// 		if err := server.Serve(lis); err != nil {
// 			log.Fatalf("Server exited with error: %v", err)
// 		}
// 	}()
// 	return server
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

// 	client := thrylos.NewBlockchainServiceClient(conn)

// 	// Prepare and send the request using FlatBuffers
// 	builder := flatbuffers.NewBuilder(0)
// 	txnID := builder.CreateString("transaction-id")
// 	prevTxID := builder.CreateString("prev-tx-id")
// 	newTxID := builder.CreateString("new-tx-id")
// 	ownerAddr := builder.CreateString("owner-address-example")
// 	recipientAddr := builder.CreateString("recipient-address-example")
// 	signature := builder.CreateByteVector([]byte("transaction-signature"))
// 	sender := builder.CreateString("sender-address")

// 	// Start the UTXOs
// 	thrylos.UTXOStart(builder)
// 	thrylos.UTXOAddTransactionId(builder, prevTxID)
// 	thrylos.UTXOAddIndex(builder, 0)
// 	thrylos.UTXOAddOwnerAddress(builder, ownerAddr)
// 	thrylos.UTXOAddAmount(builder, 50)
// 	inputUTXO := thrylos.UTXOEnd(builder)

// 	thrylos.UTXOStart(builder)
// 	thrylos.UTXOAddTransactionId(builder, newTxID)
// 	thrylos.UTXOAddIndex(builder, 0)
// 	thrylos.UTXOAddOwnerAddress(builder, recipientAddr)
// 	thrylos.UTXOAddAmount(builder, 50)
// 	outputUTXO := thrylos.UTXOEnd(builder)

// 	// Create Transaction
// 	thrylos.TransactionStart(builder)
// 	thrylos.TransactionAddId(builder, txnID)
// 	thrylos.TransactionAddTimestamp(builder, time.Now().Unix())
// 	thrylos.TransactionAddInputs(builder, inputUTXO)
// 	thrylos.TransactionAddOutputs(builder, outputUTXO)
// 	thrylos.TransactionAddSignature(builder, signature)
// 	thrylos.TransactionAddSender(builder, sender)
// 	transaction := thrylos.TransactionEnd(builder)

// 	thrylos.TransactionRequestStart(builder)
// 	thrylos.TransactionRequestAddTransaction(builder, transaction)
// 	requestOffset := thrylos.TransactionRequestEnd(builder)
// 	builder.Finish(requestOffset)

// 	r, err := client.SubmitTransaction(ctx, builder)
// 	assert.NoError(t, err)
// 	assert.NotNil(t, r)

// 	// Read the response
// 	response := thrylos.GetRootAsTransactionResponse(r.FinishedBytes(), 0)
// 	assert.Equal(t, "Transaction added successfully", string(response.Status()))
// }

// // go test -v -timeout 30s -run ^TestBlockTimeWithGRPC$ github.com/thrylos-labs/thrylos/cmd/thrylosnode

// func TestBlockTimeWithGRPC(t *testing.T) {
// 	server := startMockServer() // Start your in-memory gRPC server
// 	defer server.Stop()

// 	conn, err := grpc.Dial("", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
// 	if err != nil {
// 		t.Fatalf("Failed to dial server: %v", err)
// 	}
// 	defer conn.Close()
// 	client := thrylos.NewBlockchainServiceClient(conn)

// 	numTransactions := 1000
// 	transactionsPerBlock := 100
// 	var wg sync.WaitGroup
// 	var blockFinalizeTimes []time.Duration

// 	start := time.Now()

// 	for i := 0; i < numTransactions; i += transactionsPerBlock {
// 		wg.Add(1)
// 		go func(startIndex int) {
// 			defer wg.Done()
// 			blockStartTime := time.Now()

// 			var blockTransactions []*thrylos.Transaction
// 			for j := startIndex; j < startIndex+transactionsPerBlock && j < numTransactions; j++ {
// 				txID := fmt.Sprintf("tx%d", j)
// 				transaction := &thrylos.Transaction{
// 					Id:        txID,
// 					Timestamp: time.Now().Unix(),
// 					Inputs:    []*thrylos.UTXO{{TransactionId: "tx0", Index: 0, OwnerAddress: "Alice", Amount: 100}},
// 					Outputs:   []*thrylos.UTXO{{TransactionId: txID, Index: 0, OwnerAddress: "Bob", Amount: 100}},
// 				}
// 				_, edPrivateKey, _ := ed25519.GenerateKey(rand.Reader)
// 				txBytes, _ := json.Marshal(transaction)
// 				edSignature := ed25519.Sign(edPrivateKey, txBytes)
// 				transaction.Signature = edSignature

// 				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
// 				_, err := client.SubmitTransaction(ctx, &thrylos.TransactionRequest{Transaction: transaction})
// 				cancel()
// 				if err != nil {
// 					t.Errorf("Error submitting transaction %d: %v", j, err)
// 					continue
// 				}
// 				blockTransactions = append(blockTransactions, transaction)
// 			}

// 			time.Sleep(time.Millisecond * 500) // Simulate block finalization
// 			blockEndTime := time.Now()
// 			blockFinalizeTimes = append(blockFinalizeTimes, blockEndTime.Sub(blockStartTime))
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
