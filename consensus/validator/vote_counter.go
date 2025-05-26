package validator

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/thrylos-labs/thrylos/network" // <--- Import network package
	"github.com/thrylos-labs/thrylos/types"
	// <--- Import types package for types.Vote
)

type NodeInterface interface {
	GetActiveValidators() []string
	IsActiveValidator(address string) bool
	GetStakeholders() map[string]int64
	ConfirmBlock(blockNumber int32)
	// Add a method to get this node's own address if it's not directly in VoteCounter
	// GetNodeAddress() string
}

type VoteCounter struct {
	mu            sync.RWMutex
	votes         map[string][]types.Vote
	node          NodeInterface
	isDesignated  bool
	requiredVotes int
	libp2pManager *network.Libp2pManager // <--- NEW: Reference to the Libp2p network manager
	nodeAddress   string                 // <--- NEW: This node's own address for votes
}

// It now accepts the Libp2pManager and this node's address.
func NewVoteCounter(node NodeInterface, isDesignated bool, libp2pManager *network.Libp2pManager, nodeAddress string) *VoteCounter { // <--- ADD libp2pManager, nodeAddress
	if libp2pManager == nil { // Validate crucial dependency
		log.Panic("FATAL: NewVoteCounter called with nil Libp2pManager")
	}
	if nodeAddress == "" { // Validate this node's address
		log.Panic("FATAL: NewVoteCounter called with empty nodeAddress")
	}

	counter := &VoteCounter{
		votes:         make(map[string][]types.Vote),
		node:          node,
		isDesignated:  isDesignated,
		libp2pManager: libp2pManager, // <--- Store it
		nodeAddress:   nodeAddress,   // <--- Store it
	}

	if node != nil && len(node.GetActiveValidators()) > 0 {
		counter.requiredVotes = (2*len(node.GetActiveValidators()) + 2) / 3
	}

	return counter
}

// GetVoteCount returns the number of valid votes for a validator
func (vc *VoteCounter) GetVoteCount(validatorID string) int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	// Only count recent votes (within last minute) from valid validators
	cutoff := time.Now().Add(-1 * time.Minute)
	validVotes := 0

	for _, vote := range vc.votes[validatorID] {
		if vote.Timestamp.After(cutoff) && vc.isValidVoter(vote.VoterNode) {
			validVotes++
		}
	}

	return validVotes
}

// AddVote adds a vote for a validator with additional validation
func (vc *VoteCounter) AddVote(vote types.Vote) error { // <--- PARAMETER TYPE CHANGED TO types.Vote
	// Only the designated vote counter node should aggregate votes
	if !vc.isDesignated {
		return fmt.Errorf("this node is not the designated vote counter to add votes")
	}

	vc.mu.Lock()
	defer vc.mu.Unlock()

	// Verify voter is an active validator
	if !vc.node.IsActiveValidator(vote.VoterNode) {
		return fmt.Errorf("vote from non-validator node rejected: %s", vote.VoterNode)
	}

	// Check for duplicate votes (based on voter and block number within a recent timeframe)
	if vc.hasVotedAlready(vote.VoterNode, vote.BlockNumber) {
		return fmt.Errorf("duplicate vote rejected from node: %s for block %d",
			vote.VoterNode, vote.BlockNumber)
	}

	// Initialize votes slice if needed for this validator
	if vc.votes[vote.ValidatorID] == nil { // <--- Using ValidatorID as the map key
		vc.votes[vote.ValidatorID] = make([]types.Vote, 0)
	}

	// Add the vote to the local tally
	vc.votes[vote.ValidatorID] = append(vc.votes[vote.ValidatorID], vote)

	log.Printf("INFO: Added vote from %s for block %d (target validator: %s, pass: %t)",
		vote.VoterNode, vote.BlockNumber, vote.ValidatorID, vote.ValidationPass)

	// --- BROADCAST THE VOTE VIA LIBP2P (ONLY IF IT ORIGINATED FROM THIS NODE) ---
	// This is critical to prevent broadcasting messages received from other peers.
	if vote.VoterNode == vc.nodeAddress { // Check if this node is the originator of *this specific vote*
		if vc.libp2pManager != nil {
			log.Printf("INFO: Attempting to broadcast vote for block %d from %s via Libp2p.", vote.BlockNumber, vote.VoterNode)
			if err := vc.libp2pManager.BroadcastVote(vote); err != nil { // Call BroadcastVote on Libp2pManager
				log.Printf("WARN: Failed to broadcast vote for block %d (from %s) via Libp2p: %v", vote.BlockNumber, vote.VoterNode, err)
			} else {
				log.Printf("INFO: Successfully broadcast vote for block %d (from %s) via Libp2p.", vote.BlockNumber, vote.VoterNode)
			}
		} else {
			log.Printf("WARN: Libp2pManager not available in VoteCounter, cannot broadcast vote for block %d (from %s).", vote.BlockNumber, vote.VoterNode)
		}
	}
	// --- END BROADCAST ---

	// Check if we've reached 2/3 majority
	if vc.HasSuperMajority(vote.ValidatorID) { // <--- Using ValidatorID
		log.Printf("Achieved 2/3 majority for block %d (target validator: %s)", vote.BlockNumber, vote.ValidatorID)
		vc.node.ConfirmBlock(vote.BlockNumber)
	}

	return nil
}

// isValidVoter checks if the voter is an active validator
func (vc *VoteCounter) isValidVoter(voterAddress string) bool {
	return vc.node.IsActiveValidator(voterAddress)
}

// hasVotedAlready checks for duplicate votes
func (vc *VoteCounter) hasVotedAlready(voterNode string, blockNum int32) bool {
	// Check votes for this block number
	for _, votes := range vc.votes { // Use _ instead of validatorID since we don't use it
		for _, vote := range votes {
			if vote.VoterNode == voterNode && vote.BlockNumber == blockNum {
				// Only consider recent votes
				if time.Since(vote.Timestamp) < time.Minute {
					return true
				}
			}
		}
	}
	return false
}

// HasSuperMajority checks if a validator has received 2/3 majority votes
func (vc *VoteCounter) HasSuperMajority(validatorID string) bool {
	count := vc.GetVoteCount(validatorID)
	return count >= vc.requiredVotes &&
		count >= (2*len(vc.node.GetActiveValidators())+2)/3
}

// ClearOldVotes removes votes older than 1 minute
func (vc *VoteCounter) ClearOldVotes() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Minute)
	for validatorID := range vc.votes {
		validVotes := make([]types.Vote, 0)
		for _, vote := range vc.votes[validatorID] {
			if vote.Timestamp.After(cutoff) {
				validVotes = append(validVotes, vote)
			}
		}
		vc.votes[validatorID] = validVotes
	}
}
