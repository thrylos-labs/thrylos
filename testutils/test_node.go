package testutils

import (
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/thrylos-labs/thrylos/core/chain"
	"github.com/thrylos-labs/thrylos/core/consensus/staking"
	"github.com/thrylos-labs/thrylos/core/network"
	"github.com/thrylos-labs/thrylos/core/node"
	"github.com/thrylos-labs/thrylos/shared"
)

// Add PeerConnection definition in testutils
type PeerConnection struct {
	Address   string
	IsInbound bool
	LastSeen  time.Time
}

func NewTestNode(address string, knownPeers []string, dataDir string, blockchain *chain.Blockchain) *node.Node {
	stakingService := staking.NewStakingService(chain.blockchain)

	return &node.Node{
		Address:              address,
		Peers:                make(map[string]*network.PeerConnection), // Use local PeerConnection type
		Blockchain:           blockchain,
		PublicKeyMap:         make(map[string]mldsa44.PublicKey),
		ResponsibleUTXOs:     make(map[string]shared.UTXO),
		WebSocketConnections: make(map[string]*network.WebSocketConnection),
		StakingService:       stakingService,
		BlockTrigger:         make(chan struct{}, 1),
		MaxInbound:           30,
		MaxOutbound:          20,
	}
}
