package main

// func main() {
// 	var wg sync.WaitGroup
// 	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
// 	if err != nil {
// 		log.Fatalf("Did not connect: %v", err)
// 	}
// 	defer conn.Close()

// 	client := thrylos.NewBlockchainServiceClient(conn)

// 	numTransactions := 1000
// 	wg.Add(numTransactions)

// 	for i := 0; i < numTransactions; i++ {
// 		go func(txnID int) {
// 			defer wg.Done()
// 			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 			defer cancel()

// 			builder := flatbuffers.NewBuilder(0)
// 			transactionId := builder.CreateString("transaction-id-" + strconv.Itoa(txnID))
// 			sender := builder.CreateString("sender-address")

// 			thrylos.TransactionStart(builder)
// 			thrylos.TransactionAddId(builder, transactionId)
// 			thrylos.TransactionAddSender(builder, sender)
// 			transaction := thrylos.TransactionEnd(builder)

// 			thrylos.TransactionRequestStart(builder)
// 			thrylos.TransactionRequestAddTransaction(builder, transaction)
// 			builder.Finish(thrylos.TransactionRequestEnd(builder))

// 			// Create a gRPC-compliant message from the FlatBuffers builder
// 			msg := &TransactionMessage{Data: builder.FinishedBytes()}
// 			if _, err := client.SubmitTransaction(ctx, msg); err != nil {
// 				log.Printf("Could not submit transaction %d: %v", txnID, err)
// 			}
// 		}(i)
// 	}

// 	wg.Wait()
// }
