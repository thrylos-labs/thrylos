package validator

// type NodeInterface interface {
// 	GetActiveValidators() []string
// 	IsActiveValidator(address string) bool
// 	GetStakeholders() map[string]int64
// 	ConfirmBlock(blockNumber int32)
// }

// type Vote struct {
// 	ValidatorAddrss address.Address
// 	BlockNumber     int32
// 	BlockHash       hash.Hash
// 	ValidationPass  bool // Result of validation
// 	Timestamp       time.Time
// 	VoterNode       string
// }

// type VoteCounter struct {
// 	mu            sync.RWMutex
// 	votes         map[string][]Vote
// 	node          NodeInterface // Changed from *Node to NodeInterface
// 	isDesignated  bool
// 	requiredVotes int
// }

// func NewVoteCounter(node NodeInterface, isDesignated bool) *VoteCounter {
// 	counter := &VoteCounter{
// 		votes:        make(map[string][]Vote),
// 		node:         node,
// 		isDesignated: isDesignated,
// 	}

// 	// Calculate 2/3 of validators
// 	if node != nil && len(node.GetActiveValidators()) > 0 {
// 		counter.requiredVotes = (2*len(node.GetActiveValidators()) + 2) / 3
// 	}

// 	return counter
// }

// // GetVoteCount returns the number of valid votes for a validator
// func (vc *VoteCounter) GetVoteCount(validatorID string) int {
// 	vc.mu.RLock()
// 	defer vc.mu.RUnlock()

// 	// Only count recent votes (within last minute) from valid validators
// 	cutoff := time.Now().Add(-1 * time.Minute)
// 	validVotes := 0

// 	for _, vote := range vc.votes[validatorID] {
// 		if vote.Timestamp.After(cutoff) && vc.isValidVoter(vote.VoterNode) {
// 			validVotes++
// 		}
// 	}

// 	return validVotes
// }

// // AddVote adds a vote for a validator with additional validation
// func (vc *VoteCounter) AddVote(vote Vote) error {
// 	if !vc.isDesignated {
// 		return fmt.Errorf("this node is not the designated vote counter")
// 	}

// 	vc.mu.Lock()
// 	defer vc.mu.Unlock()

// 	// Verify voter is an active validator using interface method
// 	if !vc.node.IsActiveValidator(vote.VoterNode) {
// 		return fmt.Errorf("vote from non-validator node rejected: %s", vote.VoterNode)
// 	}

// 	// Check for duplicate votes using block number
// 	if vc.hasVotedAlready(vote.VoterNode, vote.BlockNumber) {
// 		return fmt.Errorf("duplicate vote rejected from node: %s for block %d",
// 			vote.VoterNode, vote.BlockNumber)
// 	}

// 	// Initialize votes slice if needed
// 	if vc.votes[vote.ValidatorAddrss.String()] == nil {
// 		vc.votes[vote.ValidatorAddrss.String()] = make([]Vote, 0)
// 	}

// 	vc.votes[vote.ValidatorAddrss.String()] = append(vc.votes[vote.ValidatorAddrss.String()], vote)

// 	// Check if we've reached 2/3 majority
// 	if vc.HasSuperMajority(vote.ValidatorAddrss.String()) {
// 		log.Printf("Achieved 2/3 majority for block %d", vote.BlockNumber)
// 		// Use interface method ConfirmBlock instead of confirmBlock
// 		vc.node.ConfirmBlock(vote.BlockNumber)
// 	}

// 	return nil
// }

// // isValidVoter checks if the voter is an active validator
// func (vc *VoteCounter) isValidVoter(voterAddress string) bool {
// 	return vc.node.IsActiveValidator(voterAddress)
// }

// // hasVotedAlready checks for duplicate votes
// func (vc *VoteCounter) hasVotedAlready(voterNode string, blockNum int32) bool {
// 	// Check votes for this block number
// 	for _, votes := range vc.votes { // Use _ instead of validatorID since we don't use it
// 		for _, vote := range votes {
// 			if vote.VoterNode == voterNode && vote.BlockNumber == blockNum {
// 				// Only consider recent votes
// 				if time.Since(vote.Timestamp) < time.Minute {
// 					return true
// 				}
// 			}
// 		}
// 	}
// 	return false
// }

// // HasSuperMajority checks if a validator has received 2/3 majority votes
// func (vc *VoteCounter) HasSuperMajority(validatorID string) bool {
// 	count := vc.GetVoteCount(validatorID)
// 	return count >= vc.requiredVotes &&
// 		count >= (2*len(vc.node.GetActiveValidators())+2)/3
// }

// // ClearOldVotes removes votes older than 1 minute
// func (vc *VoteCounter) ClearOldVotes() {
// 	vc.mu.Lock()
// 	defer vc.mu.Unlock()

// 	cutoff := time.Now().Add(-1 * time.Minute)
// 	for validatorID := range vc.votes {
// 		validVotes := make([]Vote, 0)
// 		for _, vote := range vc.votes[validatorID] {
// 			if vote.Timestamp.After(cutoff) {
// 				validVotes = append(validVotes, vote)
// 			}
// 		}
// 		vc.votes[validatorID] = validVotes
// 	}
// }
