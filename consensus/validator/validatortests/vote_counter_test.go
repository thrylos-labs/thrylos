package validatortests

// Interface definition
// type BlockchainValidatorNewInterface interface {
// 	IsActiveValidator(address string) bool
// 	GetActiveValidators() []string
// 	GetStakeholders() map[string]int64 // Add this method to interface
// }

// // Our test blockchain that implements needed interface
// type TestBlockchain struct {
// 	ActiveValidators []string
// 	Stakeholders     map[string]int64
// }

// func (tb *TestBlockchain) GetStakeholders() map[string]int64 {
// 	return tb.Stakeholders
// }

// func (tb *TestBlockchain) IsActiveValidator(address string) bool {
// 	for _, v := range tb.ActiveValidators {
// 		if v == address {
// 			return true
// 		}
// 	}
// 	return false
// }

// func (tb *TestBlockchain) GetActiveValidators() []string {
// 	return tb.ActiveValidators
// }

// // Test version of Node with just what we need
// type TestNode struct {
// 	Address    string
// 	blockchain BlockchainValidatorInterface
// 	votes      map[string][]Vote // Add for testing
// }

// func (tn *TestNode) GetActiveValidators() []string {
// 	return tn.blockchain.GetActiveValidators()
// }

// func (tn *TestNode) IsActiveValidator(address string) bool {
// 	return tn.blockchain.IsActiveValidator(address)
// }

// func (tn *TestNode) GetStakeholders() map[string]int64 {
// 	return tn.blockchain.GetStakeholders()
// }

// func (tn *TestNode) ConfirmBlock(blockNumber int32) {
// 	// For testing, just log the confirmation
// 	log.Printf("Test node confirmed block: %d", blockNumber)
// }

// func newTestBlockchain() *TestBlockchain {
// 	return &TestBlockchain{
// 		ActiveValidators: []string{"validator1", "validator2", "validator3"},
// 		Stakeholders: map[string]int64{
// 			"validator1": 1000,
// 			"validator2": 2000,
// 			"validator3": 3000,
// 		},
// 	}
// }

// func TestVoteCounter_AddVote(t *testing.T) {
// 	testBC := newTestBlockchain()
// 	testNode := &TestNode{
// 		Address:    "testNode",
// 		blockchain: testBC,
// 	}

// 	// Create vote counter
// 	voteCounter := NewVoteCounter(testNode, true)

// 	// Test adding a valid vote
// 	vote := Vote{
// 		ValidatorID:    "validator3",
// 		BlockNumber:    1,
// 		BlockHash:      []byte("testhash"),
// 		ValidationPass: true,
// 		Timestamp:      time.Now(),
// 		VoterNode:      "validator1",
// 	}

// 	err := voteCounter.AddVote(vote)
// 	if err != nil {
// 		t.Errorf("Failed to add valid vote: %v", err)
// 	}

// 	// Verify vote count
// 	count := voteCounter.GetVoteCount("validator3")
// 	if count != 1 {
// 		t.Errorf("Expected vote count 1, got %d", count)
// 	}
// }

// func TestVoteCounter_RejectDuplicateVotes(t *testing.T) {
// 	mockBC := NewMockBlockchainForValidator()
// 	mockNode := &Node{
// 		Address:    "testNode",
// 		Blockchain: mockBC,
// 	}

// 	voteCounter := NewVoteCounter(mockNode, true)

// 	// Add first vote
// 	vote1 := Vote{
// 		ValidatorID:    "validator3",
// 		BlockNumber:    1,
// 		ValidationPass: true,
// 		Timestamp:      time.Now(),
// 		VoterNode:      "validator1",
// 	}

// 	err := voteCounter.AddVote(vote1)
// 	if err != nil {
// 		t.Errorf("Failed to add first vote: %v", err)
// 	}

// 	// Try to add duplicate vote
// 	err = voteCounter.AddVote(vote1)
// 	if err == nil {
// 		t.Error("Expected error for duplicate vote, got nil")
// 	}
// }

// func TestVoteCounter_SuperMajority(t *testing.T) {
// 	mockBC := NewMockBlockchainForValidator()
// 	mockNode := &Node{
// 		Address:    "testNode",
// 		Blockchain: mockBC,
// 	}

// 	voteCounter := NewVoteCounter(mockNode, true)

// 	// Add votes from different validators
// 	validators := []string{"validator1", "validator2", "validator3"}
// 	for _, validator := range validators {
// 		vote := Vote{
// 			ValidatorID:    "validator3", // voting for validator3
// 			BlockNumber:    1,
// 			ValidationPass: true,
// 			Timestamp:      time.Now(),
// 			VoterNode:      validator,
// 		}

// 		err := voteCounter.AddVote(vote)
// 		if err != nil {
// 			t.Errorf("Failed to add vote from %s: %v", validator, err)
// 		}
// 	}

// 	// Should have super majority (2/3 of validators)
// 	if !voteCounter.HasSuperMajority("validator3") {
// 		t.Error("Expected super majority to be achieved")
// 	}
// }

// func TestVoteCounter_NonDesignatedNode(t *testing.T) {
// 	mockBC := NewMockBlockchainForValidator()
// 	mockNode := &Node{
// 		Address:    "testNode",
// 		Blockchain: mockBC,
// 	}

// 	// Create non-designated vote counter
// 	voteCounter := NewVoteCounter(mockNode, false)

// 	vote := Vote{
// 		ValidatorID:    "validator3",
// 		BlockNumber:    1,
// 		ValidationPass: true,
// 		Timestamp:      time.Now(),
// 		VoterNode:      "validator1",
// 	}

// 	// Should reject votes since not designated counter
// 	err := voteCounter.AddVote(vote)
// 	if err == nil {
// 		t.Error("Expected error when adding vote to non-designated counter")
// 	}
// }

// func TestVoteCounter_ExpiredVotes(t *testing.T) {
// 	mockBC := NewMockBlockchainForValidator()
// 	mockNode := &Node{
// 		Address:    "testNode",
// 		Blockchain: mockBC,
// 	}

// 	voteCounter := NewVoteCounter(mockNode, true)

// 	// Add an old vote
// 	oldVote := Vote{
// 		ValidatorID:    "validator3",
// 		BlockNumber:    1,
// 		ValidationPass: true,
// 		Timestamp:      time.Now().Add(-2 * time.Minute), // 2 minutes old
// 		VoterNode:      "validator1",
// 	}

// 	err := voteCounter.AddVote(oldVote)
// 	if err != nil {
// 		t.Errorf("Failed to add old vote: %v", err)
// 	}

// 	// Clear old votes
// 	voteCounter.ClearOldVotes()

// 	// Check vote count after clearing
// 	count := voteCounter.GetVoteCount("validator3")
// 	if count != 0 {
// 		t.Errorf("Expected 0 votes after clearing old votes, got %d", count)
// 	}
// }
