package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	pb "github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/shared"
	"google.golang.org/grpc"
)

func main() {
	sender := flag.String("sender", "", "Sender address")
	receiver := flag.String("receiver", "", "Receiver address")
	amount := flag.Int("amount", 0, "Amount to transfer")
	grpcAddress := flag.String("grpcAddress", "localhost:50051", "gRPC server address")
	flag.Parse()

	if *sender == "" || *receiver == "" || *amount == 0 {
		log.Fatal("Sender, receiver, and amount must be provided")
	}

	// Generate or retrieve keys and AES key
	_, senderPrivateKey, _ := shared.GenerateEd25519Keys() // Ideally, you would load this from secure storage
	aesKey, _ := shared.GenerateAESKey()

	inputs := []shared.UTXO{{TransactionID: "prevTxID", Index: 0, OwnerAddress: *sender, Amount: 100}} // Example input
	outputs := []shared.UTXO{{TransactionID: "newTxID", Index: 0, OwnerAddress: *receiver, Amount: *amount}}

	// Create and sign the transaction
	transaction, err := shared.CreateAndSignTransaction("tx123", *sender, inputs, outputs, senderPrivateKey, aesKey)
	if err != nil {
		log.Fatalf("Failed to create and sign transaction: %v", err)
	}

	fmt.Printf("Transaction created and signed successfully: %+v\n", transaction)

	// Setup gRPC connection
	conn, err := grpc.Dial(*grpcAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect to gRPC server: %v", err)
	}
	defer conn.Close()

	client := pb.NewBlockchainServiceClient(conn)
	transactionReq := &pb.TransactionRequest{
		Transaction: shared.ConvertToProtoTransaction(transaction),
	}

	// Send the transaction
	response, err := client.SubmitTransaction(context.Background(), transactionReq)
	if err != nil {
		log.Fatalf("Failed to submit transaction: %v", err)
	}

	fmt.Printf("Transaction submission response: %s\n", response.Status)
}
