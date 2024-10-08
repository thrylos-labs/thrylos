package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type SimpleGasEstimator struct{}

func (e *SimpleGasEstimator) FetchGasEstimate(dataSize int, balance int64) (int, error) {
	// For simplicity, return a constant gas fee
	return 1, nil
}

func main() {
	sender := flag.String("sender", "", "Sender address")
	receiver := flag.String("receiver", "", "Receiver address")
	amount := flag.Int("amount", 0, "Amount to transfer")
	grpcAddress := flag.String("grpcAddress", "localhost:50051", "gRPC server address")
	flag.Parse()

	var amount64 int64 = int64(*amount)

	if *sender == "" || *receiver == "" || *amount == 0 {
		log.Fatal("Sender, receiver, and amount must be provided")
	}

	// Generate or retrieve keys and AES key
	_, senderPrivateKey, mnemonic, err := shared.GenerateEd25519Keys() // Capture mnemonic for backup and error handling
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}
	// You might want to log or securely store the mnemonic somewhere
	fmt.Println("Save this mnemonic in a secure place:", mnemonic)

	aesKey, err := shared.GenerateAESKey()
	if err != nil {
		log.Fatalf("Failed to generate AES key: %v", err)
	}

	inputs := []shared.UTXO{{TransactionID: "prevTxID", Index: 0, OwnerAddress: *sender, Amount: 100}} // Example input
	outputs := []shared.UTXO{{TransactionID: "newTxID", Index: 0, OwnerAddress: *receiver, Amount: *&amount64}}

	// Create an instance of the gas estimator
	estimator := &SimpleGasEstimator{}

	// Create and sign the transaction
	transaction, err := shared.CreateAndSignTransaction("tx123", *sender, inputs, outputs, senderPrivateKey, aesKey, estimator)
	if err != nil {
		log.Fatalf("Failed to create and sign transaction: %v", err)
	}

	fmt.Printf("Transaction created and signed successfully: %+v\n", transaction)

	// Load TLS credentials from file
	creds, err := credentials.NewClientTLSFromFile("../../localhost.crt", "localhost")
	if err != nil {
		log.Fatalf("could not load TLS cert: %s", err)
	}

	// Setup gRPC connection
	conn, err := grpc.Dial(*grpcAddress, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := thrylos.NewBlockchainServiceClient(conn)

	// Convert transaction to protobuf format
	protoTx, err := shared.ConvertToProtoTransaction(transaction)
	if err != nil {
		log.Fatalf("Failed to convert transaction to protobuf: %v", err)
	}

	transactionReq := &thrylos.TransactionRequest{
		Transaction: protoTx,
	}

	// Send the transaction
	response, err := client.SubmitTransaction(context.Background(), transactionReq)
	if err != nil {
		log.Fatalf("Failed to submit transaction: %v", err)
	}

	fmt.Printf("Transaction submission response: %s\n", response.Status)
}
