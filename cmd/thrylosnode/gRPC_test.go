package main

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	pb "github.com/thrylos-labs/thrylos"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func init() {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	pb.RegisterBlockchainServiceServer(s, &mockServer{})
	go func() {
		if err := s.Serve(lis); err != nil {
			panic("Server exited with error: " + err.Error())
		}
	}()
}

func (m *mockServer) SubmitTransaction(ctx context.Context, req *pb.TransactionRequest) (*pb.TransactionResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*pb.TransactionResponse), args.Error(1)
}

func TestSubmitTransaction(t *testing.T) {
	// Initialize the mock server
	srv := &mockServer{}
	s := grpc.NewServer()
	pb.RegisterBlockchainServiceServer(s, srv)

	lis := bufconn.Listen(1024 * 1024)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Fatalf("Server exited with error: %v", err)
		}
	}()
	defer s.Stop()

	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(bufDialer(lis)), grpc.WithInsecure())
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewBlockchainServiceClient(conn)

	// Prepare the request
	req := &pb.TransactionRequest{
		Transaction: &pb.Transaction{
			Id: "tx-123",
			Inputs: []*pb.Input{{ // Make sure the input details are accurate
				PreviousTx:   "prev-tx-id",
				Index:        0,
				Signature:    "signature-example",
				OwnerAddress: "owner-address-example",
			}},
			Outputs: []*pb.Output{{
				Amount:  100,
				Address: "recipient-address-example",
			}},
		},
	}

	// Setup expectations
	srv.On("SubmitTransaction", mock.AnythingOfType("*context.valueCtx"), req).Return(&pb.TransactionResponse{Status: "OK"}, nil)

	// Perform the test
	resp, err := client.SubmitTransaction(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "OK", resp.Status)

	// Ensure all expected calls were made
	srv.AssertExpectations(t)
}

func bufDialer(lis *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
}

type mockServer struct {
	pb.UnimplementedBlockchainServiceServer
	mock.Mock
}
