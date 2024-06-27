package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/thrylos-labs/thrylos"
	pb "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/core"
	"github.com/thrylos-labs/thrylos/database"
	"github.com/thrylos-labs/thrylos/shared"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type server struct {
	pb.UnimplementedBlockchainServiceServer
	db           *database.BlockchainDB       // Include a pointer to BlockchainDB
	PublicKeyMap map[string]ed25519.PublicKey // Maps sender addresses to their public keys
	hasherPool   *XOFPool                     // Add the hasher pool here

}

func NewServer(db *database.BlockchainDB) *server {
	pool := NewXOFPool(10) // Adjust the pool size based on expected load

	return &server{
		db:           db,
		PublicKeyMap: make(map[string]ed25519.PublicKey),
		hasherPool:   pool,
	}
}

func (s *server) SubmitTransactionBatch(ctx context.Context, req *thrylos.TransactionBatchRequest) (*thrylos.TransactionBatchResponse, error) {
	if req == nil || len(req.Transactions) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Transaction batch request is nil or empty")
	}

	var failedTransactions []*thrylos.FailedTransaction // Use the new FailedTransaction message
	for _, transaction := range req.Transactions {
		if err := s.processTransaction(transaction); err != nil {
			log.Printf("Failed to process transaction %s: %v", transaction.Id, err)
			failedTransaction := &thrylos.FailedTransaction{
				TransactionId: transaction.Id,
				ErrorMessage:  err.Error(),
			}
			failedTransactions = append(failedTransactions, failedTransaction)
		}
	}

	response := &thrylos.TransactionBatchResponse{
		Status:             "Processed with some errors",
		FailedTransactions: failedTransactions,
	}

	if len(failedTransactions) == 0 {
		response.Status = "Batch processed successfully"
	}

	return response, nil
}

type XOFPool struct {
	pool chan blake2b.XOF
}

func NewXOFPool(size int) *XOFPool {
	pool := make(chan blake2b.XOF, size)
	for i := 0; i < size; i++ {
		xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil) // Adjust parameters as needed
		if err != nil {
			log.Printf("Failed to create XOF: %v", err)
			continue
		}
		pool <- xof
	}
	return &XOFPool{pool: pool}
}

func (p *XOFPool) GetXOF() blake2b.XOF {
	return <-p.pool
}

func (p *XOFPool) ReleaseXOF(xof blake2b.XOF) {
	// Resetting XOF might not be straightforward; consider re-creating if necessary
	p.pool <- xof
}

func (s *server) processTransaction(transaction *thrylos.Transaction) error {
	if transaction == nil {
		return fmt.Errorf("received nil transaction")
	}

	// Acquire a hasher from the pool
	hasher := s.hasherPool.GetXOF()
	defer s.hasherPool.ReleaseXOF(hasher)

	// Serialize and hash the transaction for verification/logging
	txData, err := json.Marshal(transaction)
	if err != nil {
		return fmt.Errorf("error serializing transaction: %v", err)
	}

	// Write data to hasher and calculate the hash
	if _, err := hasher.Write(txData); err != nil {
		return fmt.Errorf("hashing error: %v", err)
	}

	// Read the hash output
	hashOutput := make([]byte, 32) // Adjust size based on your security requirements
	if _, err := hasher.Read(hashOutput); err != nil {
		return fmt.Errorf("error reading hash output: %v", err)
	}

	// Log the transaction hash (or use it in further validations)
	log.Printf("Processed transaction %s with hash %x", transaction.Id, hashOutput)

	// Continue with conversion and validation...
	// Convert thrylos.Transaction to shared.Transaction
	sharedTx := core.ThrylosToShared(transaction)
	if sharedTx == nil {
		return fmt.Errorf("conversion failed for transaction ID %s", transaction.Id)
	}

	// Validate the converted transaction
	if !s.validateTransaction(sharedTx) {
		return fmt.Errorf("validation failed for transaction ID %s", sharedTx.ID)
	}

	// Process the transaction including UTXO updates and adding the transaction to the blockchain
	return s.db.ProcessTransaction(sharedTx)
}

func (s *server) validateTransaction(tx *shared.Transaction) bool {
	if tx == nil || tx.Signature == nil {
		log.Println("Transaction or its signature is nil")
		return false
	}

	// Retrieve the sender's public key from the node's public key map
	publicKey, ok := s.PublicKeyMap[tx.Sender]
	if !ok {
		log.Printf("No public key found for sender: %s", tx.Sender)
		return false
	}

	// Serialize the transaction without its signature
	serializedTx, err := tx.SerializeWithoutSignature()
	if err != nil {
		log.Printf("Failed to serialize transaction without signature: %v", err)
		return false
	}

	// Validate the transaction signature
	if !ed25519.Verify(publicKey, serializedTx, tx.Signature) {
		log.Printf("Invalid signature for transaction ID: %s", tx.ID)
		return false
	}

	// Retrieve UTXOs required to verify inputs and calculate input sum
	var totalInputs int64 // Use int64 to match UTXO amount type
	for _, input := range tx.Inputs {
		utxo, err := shared.GetUTXO(input.TransactionID, input.Index)
		if err != nil || utxo == nil {
			log.Printf("UTXO not found or error retrieving UTXO: %v", err)
			return false
		}
		if utxo.IsSpent {
			log.Println("Referenced UTXO has already been spent")
			return false
		}
		totalInputs += utxo.Amount
	}

	// Calculate the total outputs and ensure it matches inputs (conservation of value)
	var totalOutputs int64 // Use int64 to match output amount type
	for _, output := range tx.Outputs {
		totalOutputs += output.Amount
	}

	if totalInputs != totalOutputs {
		log.Printf("Input total %d does not match output total %d for transaction ID %s", totalInputs, totalOutputs, tx.ID)
		return false
	}

	return true
}

func (s *server) addPublicKey(sender string, pubKey ed25519.PublicKey) {
	s.PublicKeyMap[sender] = pubKey
}

func (s *server) SubmitTransaction(ctx context.Context, req *pb.TransactionRequest) (*pb.TransactionResponse, error) {
	log.Printf("Received transaction request: %+v", req)
	if req == nil || req.Transaction == nil {
		return nil, status.Error(codes.InvalidArgument, "Transaction request or transaction data is nil")
	}

	log.Printf("Received transaction %s for processing", req.Transaction.Id)

	// Convert the protobuf Transaction to thrylos.Transaction type
	tx, err := ConvertProtoTransactionToThrylos(req.Transaction)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to convert transaction: %v", err)
	}

	// Process the transaction using your blockchain core logic
	err = s.db.AddTransaction(tx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Transaction failed: %v", err)
	}

	log.Printf("Transaction %s added successfully", req.Transaction.Id)
	return &pb.TransactionResponse{Status: "Transaction added successfully"}, nil
}

func ConvertProtoTransactionToThrylos(protoTx *pb.Transaction) (*thrylos.Transaction, error) {
	if protoTx == nil {
		return nil, errors.New("protoTx is nil")
	}

	thrylosInputs := make([]*thrylos.UTXO, len(protoTx.Inputs))
	for i, input := range protoTx.Inputs {
		thrylosInputs[i] = &thrylos.UTXO{
			TransactionId: input.TransactionId,
			Index:         int32(input.Index),
			OwnerAddress:  input.OwnerAddress,
			Amount:        int64(input.Amount),
		}
	}

	thrylosOutputs := make([]*thrylos.UTXO, len(protoTx.Outputs))
	for i, output := range protoTx.Outputs {
		thrylosOutputs[i] = &thrylos.UTXO{
			TransactionId: output.TransactionId,
			Index:         int32(output.Index),
			OwnerAddress:  output.OwnerAddress,
			Amount:        int64(output.Amount),
		}
	}

	return &thrylos.Transaction{
		Id:        protoTx.Id,
		Sender:    protoTx.Sender,
		Inputs:    thrylosInputs,
		Outputs:   thrylosOutputs,
		Timestamp: protoTx.Timestamp,
		Signature: protoTx.Signature,
	}, nil
}
