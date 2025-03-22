package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/thrylos-labs/thrylos/state"
	"github.com/thrylos-labs/thrylos/types"
)

type MockNetwork struct {
	mock.Mock
}

func (m *MockNetwork) SendMessage(nodeAddress string, message []byte) error {
	args := m.Called(nodeAddress, message)
	return args.Error(0)
}

func (m *MockNetwork) BroadcastMessage(message []byte) error {
	args := m.Called(message)
	return args.Error(0)
}

func (m *MockNetwork) GetPeerAddresses() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockNetwork) IsConnected(nodeAddress string) bool {
	args := m.Called(nodeAddress)
	return args.Bool(0)
}

func (m *MockNetwork) AddPeer(address string) {
	m.Called(address)
}

func (m *MockNetwork) RemovePeer(address string) {
	m.Called(address)
}

func TestStateManager(t *testing.T) {
	mockNetwork := new(MockNetwork)
	// Set up mock expectation before creating StateManager
	mockNetwork.On("BroadcastMessage", mock.Anything).Return(nil)

	sm := state.NewStateManager(mockNetwork, 4)

	t.Run("Partition Assignment", func(t *testing.T) {
		// Test each partition range
		testAddresses := []string{
			"tl1test123",
			"tl11test456",
			"tl12test789",
			"tl13testxyz",
		}

		for _, addr := range testAddresses {
			partition := sm.GetResponsiblePartition(addr)
			assert.NotNil(t, partition, "Partition should be found for address: %s", addr)
		}
	})

	t.Run("Balance Management", func(t *testing.T) {
		address := "tl1test123"
		balance := int64(1000)

		err := sm.UpdateState(address, balance, nil)
		assert.NoError(t, err)

		retrievedBalance, err := sm.GetBalance(address)
		assert.NoError(t, err)
		assert.Equal(t, balance, retrievedBalance)
	})

	t.Run("UTXO Management", func(t *testing.T) {
		address := "tl1test123"
		utxo := types.UTXO{
			TransactionID: "tx1",
			OwnerAddress:  address,
			Amount:        1000,
		}

		err := sm.UpdateState(address, 1000, &utxo)
		assert.NoError(t, err)

		utxos, err := sm.GetUTXOs(address)
		assert.NoError(t, err)
		assert.Len(t, utxos, 1)
		assert.Equal(t, utxo.TransactionID, utxos[0].TransactionID)
	})

	t.Run("State Sync", func(t *testing.T) {
		// Reset the mock expectations for this specific test
		mockNetwork.ExpectedCalls = nil
		mockNetwork.Calls = nil
		mockNetwork.On("BroadcastMessage", mock.Anything).Return(nil)

		// Get first partition for testing
		partitions := sm.GetPartitions()
		assert.NotEmpty(t, partitions, "Partitions should not be empty")

		// Explicitly call SyncPartitionState
		err := sm.SyncPartitionState(partitions[0])
		assert.NoError(t, err)

		// Verify the mock was called
		mockNetwork.AssertCalled(t, "BroadcastMessage", mock.Anything)
	})

	// Cleanup - use the accessor method instead of direct field access
	sm.StopStateSyncLoop() // This method should properly close the stopChan
}
