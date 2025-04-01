package validators

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/thrylos-labs/thrylos/types"
)

// ValidatorSelector manages the selection and coordination of validators
// for creating new blocks from pending transactions in the blockchain.
// It ensures fair selection based on stake amounts and maintains the
// synchronization of block creation across the network.

type BlockchainValidatorInterface interface {
	IsActiveValidator(address string) bool
	GetActiveValidators() []string
	GetStakeholders() map[string]int64
}

// ValidatorSelector handles the selection of validators for block creation
type ValidatorSelector struct {
	messageBus        types.MessageBusInterface
	mu                sync.RWMutex
	lastSelectedTime  time.Time
	superMajorityVote map[string]int // Track votes for each validator
	messageChannels   map[types.MessageType]chan types.Message
}

func NewValidatorSelector(messageBus types.MessageBusInterface) *ValidatorSelector {
	vs := &ValidatorSelector{
		messageBus:        messageBus,
		lastSelectedTime:  time.Now(),
		superMajorityVote: make(map[string]int),
		messageChannels:   make(map[types.MessageType]chan types.Message),
	}

	// Register message handlers
	vs.registerMessageHandlers()

	return vs
}

// processMessage handles incoming messages based on their type
func (vs *ValidatorSelector) processMessage(msg types.Message) {
	switch msg.Type {
	case types.SelectValidator:
		vs.handleSelectValidator(msg)
	case types.ProcessValidatorVote:
		vs.handleProcessValidatorVote(msg)
	case types.HasSuperMajority:
		vs.handleHasSuperMajority(msg)
	case types.CreateBlock:
		vs.handleCreateBlock(msg)
	default:
		// Unknown message type
		if msg.ResponseCh != nil {
			msg.ResponseCh <- types.Response{
				Error: fmt.Errorf("unknown message type: %s", msg.Type),
			}
		}
	}
}

// registerMessageHandlers sets up all the message handlers for the validator selector
func (vs *ValidatorSelector) registerMessageHandlers() {
	// Create channels for each message type
	messageTypes := []types.MessageType{
		types.SelectValidator,
		types.ProcessValidatorVote,
		types.HasSuperMajority,
		types.CreateBlock,
	}

	for _, msgType := range messageTypes {
		// Create a channel for this message type
		ch := make(chan types.Message)
		vs.messageChannels[msgType] = ch

		// Subscribe to the message bus
		vs.messageBus.Subscribe(msgType, ch)

		// Start a goroutine to process messages from this channel
		go func(messageType types.MessageType, channel chan types.Message) {
			for msg := range channel {
				vs.processMessage(msg)
			}
		}(msgType, ch)
	}
}

// handleSelectValidator processes SelectValidator messages
func (vs *ValidatorSelector) handleSelectValidator(msg types.Message) {
	if msg.ResponseCh == nil {
		log.Println("Warning: SelectValidator message received with no response channel")
		return
	}

	validator, err := vs.SelectNextValidator()
	msg.ResponseCh <- types.Response{
		Data:  validator,
		Error: err,
	}
}

// handleProcessValidatorVote processes ProcessValidatorVote messages
func (vs *ValidatorSelector) handleProcessValidatorVote(msg types.Message) {
	if msg.ResponseCh == nil {
		log.Println("Warning: ProcessValidatorVote message received with no response channel")
		return
	}

	voteData, ok := msg.Data.(map[string]interface{})
	if !ok {
		msg.ResponseCh <- types.Response{
			Error: fmt.Errorf("invalid vote data format"),
		}
		return
	}

	validator, ok := voteData["validator"].(string)
	if !ok {
		msg.ResponseCh <- types.Response{
			Error: fmt.Errorf("missing validator in vote data"),
		}
		return
	}

	vs.mu.Lock()
	// Increment vote count
	vs.superMajorityVote[validator]++
	count := vs.superMajorityVote[validator]
	vs.mu.Unlock()

	msg.ResponseCh <- types.Response{
		Data: map[string]interface{}{
			"validator": validator,
			"votes":     count,
		},
	}
}

// handleHasSuperMajority processes HasSuperMajority messages
func (vs *ValidatorSelector) handleHasSuperMajority(msg types.Message) {
	if msg.ResponseCh == nil {
		log.Println("Warning: HasSuperMajority message received with no response channel")
		return
	}

	validator, ok := msg.Data.(string)
	if !ok {
		msg.ResponseCh <- types.Response{
			Error: fmt.Errorf("invalid validator data format"),
		}
		return
	}

	hasMajority := vs.HasSuperMajority(validator)
	msg.ResponseCh <- types.Response{
		Data: hasMajority,
	}
}

// handleCreateBlock processes CreateBlock messages
func (vs *ValidatorSelector) handleCreateBlock(msg types.Message) {
	if msg.ResponseCh == nil {
		log.Println("Warning: CreateBlock message received with no response channel")
		return
	}

	blockData, ok := msg.Data.(map[string]interface{})
	if !ok {
		msg.ResponseCh <- types.Response{
			Error: fmt.Errorf("invalid block creation data format"),
		}
		return
	}

	validator, ok := blockData["validator"].(string)
	if !ok {
		msg.ResponseCh <- types.Response{
			Error: fmt.Errorf("missing validator in block creation data"),
		}
		return
	}

	// Request blockchain info to check if validator is active
	validatorCheckCh := make(chan types.Response)
	vs.messageBus.Publish(types.Message{
		Type:       types.IsActiveValidator,
		Data:       validator,
		ResponseCh: validatorCheckCh,
	})

	validatorCheckResp := <-validatorCheckCh
	if validatorCheckResp.Error != nil {
		msg.ResponseCh <- types.Response{
			Error: fmt.Errorf("failed to check validator status: %v", validatorCheckResp.Error),
		}
		return
	}

	isActive, ok := validatorCheckResp.Data.(bool)
	if !ok || !isActive {
		msg.ResponseCh <- types.Response{
			Error: fmt.Errorf("invalid or inactive validator: %s", validator),
		}
		return
	}

	// Request creation of block with pending transactions
	createBlockCh := make(chan types.Response)
	vs.messageBus.Publish(types.Message{
		Type: types.ProcessPendingTransactions,
		Data: map[string]interface{}{
			"validator": validator,
		},
		ResponseCh: createBlockCh,
	})

	createBlockResp := <-createBlockCh
	if createBlockResp.Error != nil {
		msg.ResponseCh <- types.Response{
			Error: fmt.Errorf("failed to process pending transactions: %v", createBlockResp.Error),
		}
		return
	}

	block, ok := createBlockResp.Data.(*types.Block)
	if !ok || block == nil {
		msg.ResponseCh <- types.Response{
			Error: fmt.Errorf("no pending transactions to process or invalid block data"),
		}
		return
	}

	// Return the created block
	msg.ResponseCh <- types.Response{
		Data: block,
	}
}

// Clean up resources when the validator selector is no longer needed
func (vs *ValidatorSelector) Cleanup() {
	// Unsubscribe from all message types
	for msgType, ch := range vs.messageChannels {
		vs.messageBus.Unsubscribe(msgType, ch)
		close(ch)
	}
}

// SelectNextValidator chooses the next validator to create a block
func (vs *ValidatorSelector) SelectNextValidator() (string, error) {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	// Get active validators through message bus
	activeValidatorsCh := make(chan types.Response)
	vs.messageBus.Publish(types.Message{
		Type:       types.GetActiveValidators,
		Data:       nil,
		ResponseCh: activeValidatorsCh,
	})

	activeValidatorsResp := <-activeValidatorsCh
	if activeValidatorsResp.Error != nil {
		return "", fmt.Errorf("failed to get active validators: %v", activeValidatorsResp.Error)
	}

	activeValidators, ok := activeValidatorsResp.Data.([]string)
	if !ok {
		return "", fmt.Errorf("invalid active validators data format")
	}

	if len(activeValidators) == 0 {
		return "", fmt.Errorf("no active validators available")
	}

	// Get stakeholders through message bus
	stakeholdersCh := make(chan types.Response)
	vs.messageBus.Publish(types.Message{
		Type:       types.GetStakeholders,
		Data:       nil,
		ResponseCh: stakeholdersCh,
	})

	stakeholdersResp := <-stakeholdersCh
	if stakeholdersResp.Error != nil {
		return "", fmt.Errorf("failed to get stakeholders: %v", stakeholdersResp.Error)
	}

	stakeholders, ok := stakeholdersResp.Data.(map[string]int64)
	if !ok {
		return "", fmt.Errorf("invalid stakeholders data format")
	}

	// Select based on stakes and votes
	selectedValidator := ""
	highestStake := int64(0)

	for _, validator := range activeValidators {
		if stake, exists := stakeholders[validator]; exists {
			// Only consider validators with super majority
			if stake > highestStake && vs.HasSuperMajority(validator) {
				highestStake = stake
				selectedValidator = validator
			}
		}
	}

	if selectedValidator == "" {
		return "", fmt.Errorf("no validator with sufficient votes and stake found")
	}

	vs.lastSelectedTime = time.Now()
	return selectedValidator, nil
}

// HasSuperMajority checks if a validator has super majority of votes
func (vs *ValidatorSelector) HasSuperMajority(validator string) bool {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	// Get total active validators through message bus
	totalValidatorsCh := make(chan types.Response)
	vs.messageBus.Publish(types.Message{
		Type:       types.GetActiveValidators,
		Data:       nil,
		ResponseCh: totalValidatorsCh,
	})

	totalValidatorsResp := <-totalValidatorsCh
	if totalValidatorsResp.Error != nil {
		log.Printf("Error getting active validators: %v", totalValidatorsResp.Error)
		return false
	}

	activeValidators, ok := totalValidatorsResp.Data.([]string)
	if !ok {
		log.Printf("Invalid active validators data format")
		return false
	}

	totalValidators := len(activeValidators)
	if totalValidators == 0 {
		return false
	}

	votes := vs.superMajorityVote[validator]
	// Super majority requires more than 2/3 of votes
	return votes > (totalValidators * 2 / 3)
}

// CreateBlockFromPendingTransactions now uses the message bus pattern
func (vs *ValidatorSelector) CreateBlockFromPendingTransactions(validator string) (*types.Block, error) {
	// Use the CreateBlock message to handle block creation
	createBlockCh := make(chan types.Response)
	vs.messageBus.Publish(types.Message{
		Type: types.CreateBlock,
		Data: map[string]interface{}{
			"validator": validator,
		},
		ResponseCh: createBlockCh,
	})

	createBlockResp := <-createBlockCh
	if createBlockResp.Error != nil {
		return nil, createBlockResp.Error
	}

	block, ok := createBlockResp.Data.(*types.Block)
	if !ok || block == nil {
		return nil, fmt.Errorf("failed to create block")
	}

	return block, nil
}
