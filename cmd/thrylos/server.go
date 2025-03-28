package main

// type server struct {
// 	thrylos.UnimplementedBlockchainServiceServer
// 	blockchain   *chain.BlockchainImpl
// 	store        types.Store                   // Changed from *database.BlockchainDB to types.Store
// 	PublicKeyMap map[string]*mldsa44.PublicKey // Changed to use mldsa44.PublicKey
// 	hasherPool   *XOFPool                      // Add the hasher pool here

// }

// func NewServer(store types.Store) *server {
// 	pool := NewXOFPool(10) // Adjust the pool size based on expected load

// 	return &server{
// 		store:        store, // Using store instead of db
// 		PublicKeyMap: make(map[string]*mldsa44.PublicKey),
// 		hasherPool:   pool,
// 	}
// }

// // server.go
// // server.go
// func (s *server) GetBalance(ctx context.Context, req *thrylos.GetBalanceRequest) (*thrylos.BalanceResponse, error) {
// 	if req.Address == "" {
// 		return nil, status.Error(codes.InvalidArgument, "Address is required")
// 	}

// 	// Create empty UTXO map for the GetBalance call
// 	utxoMap := make(map[string][]types.UTXO)

// 	// Get balance using the existing GetBalance method with UTXO map
// 	balance, err := s.store.GetBalance(req.Address, utxoMap)
// 	if err != nil {
// 		// Handle new wallet case
// 		if strings.Contains(err.Error(), "wallet not found") {
// 			balance = 700000000 // 70 Thrylos in nanoTHR
// 		} else {
// 			return nil, status.Errorf(codes.Internal, "Failed to get balance: %v", err)
// 		}
// 	}

// 	// Calculate Thrylos balance
// 	balanceThrylos := float64(balance) / 1e7

// 	return &thrylos.BalanceResponse{
// 		Balance:           balance,
// 		BalanceThrylos:    balanceThrylos,
// 		BlockchainAddress: req.Address,
// 	}, nil
// }

// // The streaming version also needs to be updated
// func (s *server) StreamBalance(req *thrylos.GetBalanceRequest, stream thrylos.BlockchainService_StreamBalanceServer) error {
// 	if req.Address == "" {
// 		return status.Error(codes.InvalidArgument, "Address is required")
// 	}

// 	// Create empty UTXO map for the GetBalance call
// 	utxoMap := make(map[string][]types.UTXO)

// 	// Send initial balance
// 	balance, err := s.db.GetBalance(req.Address, utxoMap)
// 	if err != nil {
// 		if strings.Contains(err.Error(), "wallet not found") {
// 			balance = 700000000 // 70 Thrylos in nanoTHR
// 		} else {
// 			return status.Errorf(codes.Internal, "Failed to get initial balance: %v", err)
// 		}
// 	}

// 	balanceResponse := &thrylos.BalanceResponse{
// 		Balance:           balance,
// 		BalanceThrylos:    float64(balance) / 1e7,
// 		BlockchainAddress: req.Address,
// 	}

// 	if err := stream.Send(balanceResponse); err != nil {
// 		return status.Errorf(codes.Internal, "Failed to send initial balance: %v", err)
// 	}

// 	// Set up channel for balance updates
// 	updateChan := make(chan int64, 10)
// 	defer close(updateChan)

// 	for {
// 		select {
// 		case <-stream.Context().Done():
// 			return nil
// 		case newBalance := <-updateChan:
// 			response := &thrylos.BalanceResponse{
// 				Balance:           newBalance,
// 				BalanceThrylos:    float64(newBalance) / 1e7,
// 				BlockchainAddress: req.Address,
// 			}
// 			if err := stream.Send(response); err != nil {
// 				return status.Errorf(codes.Internal, "Failed to send balance update: %v", err)
// 			}
// 		}
// 	}
// }

// func (s *server) SubmitTransactionBatch(ctx context.Context, req *thrylos.TransactionBatchRequest) (*thrylos.TransactionBatchResponse, error) {
// 	if req == nil || len(req.Transactions) == 0 {
// 		return nil, status.Error(codes.InvalidArgument, "Transaction batch request is nil or empty")
// 	}

// 	var failedTransactions []*thrylos.FailedTransaction // Use the new FailedTransaction message
// 	for _, transaction := range req.Transactions {
// 		if err := s.processTransaction(transaction); err != nil {
// 			log.Printf("Failed to process transaction %s: %v", transaction.Id, err)
// 			failedTransaction := &thrylos.FailedTransaction{
// 				TransactionId: transaction.Id,
// 				ErrorMessage:  err.Error(),
// 			}
// 			failedTransactions = append(failedTransactions, failedTransaction)
// 		}
// 	}

// 	response := &thrylos.TransactionBatchResponse{
// 		Status:             "Processed with some errors",
// 		FailedTransactions: failedTransactions,
// 	}

// 	if len(failedTransactions) == 0 {
// 		response.Status = "Batch processed successfully"
// 	}

// 	return response, nil
// }

// type XOFPool struct {
// 	pool chan blake2b.XOF
// }

// func NewXOFPool(size int) *XOFPool {
// 	pool := make(chan blake2b.XOF, size)
// 	for i := 0; i < size; i++ {
// 		xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil) // Adjust parameters as needed
// 		if err != nil {
// 			log.Printf("Failed to create XOF: %v", err)
// 			continue
// 		}
// 		pool <- xof
// 	}
// 	return &XOFPool{pool: pool}
// }

// func (p *XOFPool) GetXOF() blake2b.XOF {
// 	return <-p.pool
// }

// func (p *XOFPool) ReleaseXOF(xof blake2b.XOF) {
// 	// Resetting XOF might not be straightforward; consider re-creating if necessary
// 	p.pool <- xof
// }

// func (s *server) processTransaction(transaction *thrylos.Transaction) error {
// 	if transaction == nil {
// 		return fmt.Errorf("received nil transaction")
// 	}

// 	// Acquire a hasher from the pool
// 	hasher := s.hasherPool.GetXOF()
// 	defer s.hasherPool.ReleaseXOF(hasher)

// 	// Serialize and hash the transaction for verification/logging
// 	txData, err := json.Marshal(transaction)
// 	if err != nil {
// 		return fmt.Errorf("error serializing transaction: %v", err)
// 	}

// 	// Write data to hasher and calculate the hash
// 	if _, err := hasher.Write(txData); err != nil {
// 		return fmt.Errorf("hashing error: %v", err)
// 	}

// 	// Read the hash output
// 	hashOutput := make([]byte, 32) // Adjust size based on your security requirements
// 	if _, err := hasher.Read(hashOutput); err != nil {
// 		return fmt.Errorf("error reading hash output: %v", err)
// 	}

// 	// Log the transaction hash (or use it in further validations)
// 	log.Printf("Processed transaction %s with hash %x", transaction.Id, hashOutput)

// 	// Continue with conversion and validation...
// 	// Convert thrylos.Transaction to shared.Transaction
// 	sharedTx := processor.ThrylosToShared(transaction)
// 	if sharedTx == nil {
// 		return fmt.Errorf("conversion failed for transaction ID %s", transaction.Id)
// 	}

// 	// Validate the converted transaction
// 	if !s.validateTransaction(sharedTx) {
// 		return fmt.Errorf("validation failed for transaction ID %s", sharedTx.ID)
// 	}

// 	// Process the transaction including UTXO updates and adding the transaction to the blockchain
// 	return s.store.ProcessTransaction(sharedTx)
// }

// func (s *server) validateTransaction(tx *types.Transaction) bool {
// 	if tx == nil || tx.Signature == "" {
// 		log.Println("Transaction or its signature is empty")
// 		return false
// 	}

// 	// Retrieve the sender's public key from the node's public key map
// 	publicKey, ok := s.PublicKeyMap[tx.Sender]
// 	if !ok {
// 		log.Printf("No public key found for sender: %s", tx.Sender)
// 		return false
// 	}

// 	// Serialize the transaction without its signature
// 	serializedTx, err := tx.SerializeWithoutSignature()
// 	if err != nil {
// 		log.Printf("Failed to serialize transaction without signature: %v", err)
// 		return false
// 	}

// 	// Decode the base64-encoded signature
// 	signatureBytes, err := base64.StdEncoding.DecodeString(tx.Signature)
// 	if err != nil {
// 		log.Printf("Failed to decode signature: %v", err)
// 		return false
// 	}

// 	// Extract salt and signature from the combined signature bytes
// 	// ML-DSA44 salt is 32 bytes
// 	if len(signatureBytes) < 32 {
// 		log.Printf("Signature too short for transaction ID: %s", tx.ID)
// 		return false
// 	}
// 	salt := signatureBytes[:32]
// 	signature := signatureBytes[32:]

// 	// Validate the transaction signature using ML-DSA44
// 	if !mldsa44.Verify(publicKey, serializedTx, signature, salt) {
// 		log.Printf("Invalid signature for transaction ID: %s", tx.ID)
// 		return false
// 	}

// 	// The rest of the validation logic remains the same
// 	var totalInputs int64
// 	for _, input := range tx.Inputs {
// 		utxo, err := store.GetUTXO(input.TransactionID, input.Index)
// 		if err != nil || utxo == nil {
// 			log.Printf("UTXO not found or error retrieving UTXO: %v", err)
// 			return false
// 		}
// 		if utxo.IsSpent {
// 			log.Println("Referenced UTXO has already been spent")
// 			return false
// 		}
// 		totalInputs += utxo.Amount
// 	}

// 	var totalOutputs int64
// 	for _, output := range tx.Outputs {
// 		totalOutputs += output.Amount
// 	}

// 	if totalInputs != totalOutputs {
// 		log.Printf("Input total %d does not match output total %d for transaction ID %s", totalInputs, totalOutputs, tx.ID)
// 		return false
// 	}

// 	return true
// }

// func (s *server) addPublicKey(sender string, pubKey *mldsa44.PublicKey) {
// 	s.PublicKeyMap[sender] = pubKey
// }

// func (s *server) SubmitTransaction(ctx context.Context, req *thrylos.TransactionRequest) (*thrylos.TransactionResponse, error) {
// 	log.Printf("Received transaction request: %+v", req)
// 	if req == nil || req.Transaction == nil {
// 		return nil, status.Error(codes.InvalidArgument, "Transaction request or transaction data is nil")
// 	}

// 	log.Printf("Received transaction %s for processing", req.Transaction.Id)

// 	// Convert the protobuf Transaction to thrylos.Transaction type
// 	tx, err := ConvertProtoTransactionToThrylos(req.Transaction)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "Failed to convert transaction: %v", err)
// 	}

// 	// Process the transaction using your blockchain core logic
// 	err = s.db.AddTransaction(tx)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "Transaction failed: %v", err)
// 	}

// 	log.Printf("Transaction %s added successfully", req.Transaction.Id)
// 	return &thrylos.TransactionResponse{Status: "Transaction added successfully"}, nil
// }

// func ConvertProtoTransactionToThrylos(protoTx *thrylos.Transaction) (*thrylos.Transaction, error) {
// 	if protoTx == nil {
// 		return nil, errors.New("protoTx is nil")
// 	}

// 	thrylosInputs := make([]*thrylos.UTXO, len(protoTx.Inputs))
// 	for i, input := range protoTx.Inputs {
// 		thrylosInputs[i] = &thrylos.UTXO{
// 			TransactionId: input.TransactionId,
// 			Index:         int32(input.Index),
// 			OwnerAddress:  input.OwnerAddress,
// 			Amount:        int64(input.Amount),
// 		}
// 	}

// 	thrylosOutputs := make([]*thrylos.UTXO, len(protoTx.Outputs))
// 	for i, output := range protoTx.Outputs {
// 		thrylosOutputs[i] = &thrylos.UTXO{
// 			TransactionId: output.TransactionId,
// 			Index:         int32(output.Index),
// 			OwnerAddress:  output.OwnerAddress,
// 			Amount:        int64(output.Amount),
// 		}
// 	}

// 	return &thrylos.Transaction{
// 		Id:        protoTx.Id,
// 		Sender:    protoTx.Sender,
// 		Inputs:    thrylosInputs,
// 		Outputs:   thrylosOutputs,
// 		Timestamp: protoTx.Timestamp,
// 		Signature: protoTx.Signature,
// 	}, nil
// }
