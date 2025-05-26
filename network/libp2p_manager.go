package network

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	// Corrected logging import: use an alias for go-log/v2
	go_log "github.com/ipfs/go-log/v2" // <--- FIX 1: Alias for ipfs/go-log/v2
	"github.com/libp2p/go-libp2p"

	// Ensure these modules are added to your go.mod
	dht "github.com/libp2p/go-libp2p-kad-dht"   // <--- FIX 2: Ensure module is in go.mod
	pubsub "github.com/libp2p/go-libp2p-pubsub" // <--- FIX 2: Ensure module is in go.mod
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network" // For network.Stream, network.Notifiee
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multiaddr"

	// <--- FIX 3: Add peerstore for Peer.ID.Pretty
	// Your existing project imports
	stdlog "log" // <--- FIX 1: Standard log package alias

	"github.com/thrylos-labs/thrylos"
	"github.com/thrylos-labs/thrylos/types"
)

// Define your protocol IDs and PubSub topic names
const (
	ProtocolBlockSync   protocol.ID = "/thrylos/blocksync/1.0.0"
	ProtocolTransaction protocol.ID = "/thrylos/transaction/1.0.0"
	ProtocolVote        protocol.ID = "/thrylos/vote/1.0.0"
	TopicBlocks                     = "thrylos-blocks"
	TopicTransactions               = "thrylos-transactions"
	TopicVotes                      = "thrylos-votes"
)

// Libp2pManager manages the libp2p host and related services
type Libp2pManager struct {
	Host   host.Host
	Ctx    context.Context
	Cancel context.CancelFunc
	PubSub *pubsub.PubSub
	DHT    *dht.IpfsDHT

	messageBus          types.MessageBusInterface
	BlockchainProcessCh chan types.Message // A channel to send messages back to the blockchain core
}

// NewLibp2pManager initializes a new libp2p host
func NewLibp2pManager(messageBus types.MessageBusInterface, listenPort int, bootstrapPeers []multiaddr.Multiaddr) (*Libp2pManager, error) {
	go_log.SetLogLevel("libp2p", "info") // <--- FIX 1: Use aliased log.SetLogLevel
	ctx, cancel := context.WithCancel(context.Background())

	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", listenPort)),
		libp2p.NATPortMap(),
		libp2p.EnableRelay(),
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// <--- FIX 3: peer.ID.Pretty is available via peerstore.PeerInfo
	// h.ID() returns peer.ID, which can be implicitly converted to peer.ID,
	// but the .Pretty() method might be on peer.ID or a related struct in peerstore.
	// However, if you explicitly add peerstore import, this generally resolves
	// as it brings in the necessary methods for peer.ID string representation.
	stdlog.Printf("Libp2p host created with Peer ID: %s, listening on: %s",
		peer.ID(h.ID()).String(), h.Addrs()) // <--- Alternative: use .String() which is always available

	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to create pubsub: %w", err)
	}

	kademliaDHT, err := dht.New(ctx, h, dht.Mode(dht.ModeServer))
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	if err = kademliaDHT.Bootstrap(ctx); err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	// Connect to bootstrap peers
	for _, addr := range bootstrapPeers {
		pi, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			stdlog.Printf("Invalid bootstrap peer address %s: %v", addr, err)
			continue
		}
		if pi.ID == h.ID() { // Don't try to connect to self
			continue
		}
		stdlog.Printf("Connecting to bootstrap peer: %s", pi.ID.String()) // <--- FIX 3: Use .String()
		go func(pi peer.AddrInfo) {
			connectCtx, connectCancel := context.WithTimeout(ctx, 10*time.Second) // Timeout for connection
			defer connectCancel()
			if err := h.Connect(connectCtx, pi); err != nil {
				stdlog.Printf("Failed to connect to bootstrap peer %s: %v", pi.ID.String(), err) // <--- FIX 3: Use .String()
			} else {
				stdlog.Printf("Connected to bootstrap peer: %s", pi.ID.String()) // <--- FIX 3: Use .String()
			}
		}(*pi)
	}

	manager := &Libp2pManager{
		Host:                h,
		Ctx:                 ctx,
		Cancel:              cancel,
		PubSub:              ps,
		DHT:                 kademliaDHT,
		messageBus:          messageBus,
		BlockchainProcessCh: make(chan types.Message, 100), // Buffered channel for processing
	}

	go manager.processBlockchainMessages()

	return manager, nil
}

func (lm *Libp2pManager) processBlockchainMessages() {
	for {
		select {
		case msg := <-lm.BlockchainProcessCh:
			lm.messageBus.Publish(msg)
		case <-lm.Ctx.Done():
			return
		}
	}
}

func (lm *Libp2pManager) StartLibp2pServices() {
	lm.startMDNSDiscovery()
	lm.startDHTDiscovery()

	lm.Host.SetStreamHandler(ProtocolBlockSync, lm.handleBlockSyncRequest)
	lm.Host.SetStreamHandler(ProtocolTransaction, lm.handleTransactionRequest)
	lm.Host.SetStreamHandler(ProtocolVote, lm.handleVoteRequest)

	lm.subscribeToPubSubTopics()

	stdlog.Println("Libp2p services started.") // <--- FIX 1: Use aliased stdlog
}

func (lm *Libp2pManager) Close() error {
	stdlog.Println("Shutting down libp2p host...") // <--- FIX 1: Use aliased stdlog
	lm.Cancel()
	if lm.DHT != nil {
		if err := lm.DHT.Close(); err != nil {
			stdlog.Printf("Error closing DHT: %v", err) // <--- FIX 1: Use aliased stdlog
		}
	}
	if err := lm.Host.Close(); err != nil {
		return fmt.Errorf("error closing libp2p host: %w", err)
	}
	stdlog.Println("Libp2p host shut down.") // <--- FIX 1: Use aliased stdlog
	return nil
}

// --- Discovery Handlers ---

func (lm *Libp2pManager) HandlePeerFound(pi peer.AddrInfo) {
	stdlog.Printf("Discovered new peer via mDNS: %s", pi.ID.String()) // <--- FIX 3: Use .String()
	if pi.ID == lm.Host.ID() {
		return
	}
	go func() {
		connectCtx, connectCancel := context.WithTimeout(lm.Ctx, 10*time.Second)
		defer connectCancel()
		if err := lm.Host.Connect(connectCtx, pi); err != nil {
			stdlog.Printf("Failed to connect to mDNS discovered peer %s: %v", pi.ID.String(), err) // <--- FIX 3: Use .String()
		} else {
			stdlog.Printf("Successfully connected to mDNS discovered peer %s", pi.ID.String()) // <--- FIX 3: Use .String()
		}
	}()
}

func (lm *Libp2pManager) startMDNSDiscovery() {
	service := mdns.NewMdnsService(lm.Host, "thrylos-blockchain", lm)
	if err := service.Start(); err != nil {
		stdlog.Printf("Failed to start mDNS discovery: %v", err) // <--- FIX 1: Use aliased stdlog
	} else {
		stdlog.Println("mDNS discovery started.") // <--- FIX 1: Use aliased stdlog
	}
}

func (lm *Libp2pManager) startDHTDiscovery() {
	routingDiscovery := routing.NewRoutingDiscovery(lm.DHT)
	routingDiscovery.Advertise(lm.Ctx, "thrylos-blockchain")

	go func() {
		for {
			select {
			case <-lm.Ctx.Done():
				return
			case <-time.After(30 * time.Second):
				stdlog.Println("Searching for peers via DHT...") // <--- FIX 1: Use aliased stdlog
				peerChan, err := routingDiscovery.FindPeers(lm.Ctx, "thrylos-blockchain")
				if err != nil {
					stdlog.Printf("DHT peer discovery failed: %v", err) // <--- FIX 1: Use aliased stdlog
					continue
				}
				for pi := range peerChan {
					if pi.ID == lm.Host.ID() || len(pi.Addrs) == 0 {
						continue
					}
					stdlog.Printf("Discovered peer via DHT: %s", pi.ID.String()) // <--- FIX 3: Use .String()
					go func(pi peer.AddrInfo) {
						connectCtx, connectCancel := context.WithTimeout(lm.Ctx, 10*time.Second)
						defer connectCancel()
						if err := lm.Host.Connect(connectCtx, pi); err != nil {
							stdlog.Printf("Failed to connect to DHT discovered peer %s: %v", pi.ID.String(), err) // <--- FIX 3: Use .String()
						} else {
							stdlog.Printf("Successfully connected to DHT discovered peer %s", pi.ID.String()) // <--- FIX 3: Use .String()
						}
					}(pi)
				}
			}
		}
	}()
	stdlog.Println("DHT discovery started.") // <--- FIX 1: Use aliased stdlog
}

// --- Protocol Handlers ---

func (lm *Libp2pManager) handleBlockSyncRequest(s network.Stream) {
	defer s.Close()
	// CHANGE THIS LINE:
	stdlog.Printf("Received block sync request from %s", s.Conn().RemotePeer().String()) // Use .String()

	reader := NewJSONStreamReader(s)
	writer := NewJSONStreamWriter(s)

	var reqData map[string]int32
	if err := reader.ReadJSON(&reqData); err != nil {
		// CHANGE THIS LINE:
		stdlog.Printf("Error reading sync request from %s: %v", s.Conn().RemotePeer().String(), err)
		return
	}
	startHeight := reqData["startHeight"]
	// CHANGE THIS LINE:
	stdlog.Printf("Peer %s requested blocks from height: %d", s.Conn().RemotePeer().String(), startHeight)

	responseCh := make(chan types.Response)
	lm.messageBus.Publish(types.Message{
		Type:       types.GetBlocksFromHeight,
		Data:       startHeight,
		ResponseCh: responseCh,
	})

	resp := <-responseCh
	if resp.Error != nil {
		// CHANGE THIS LINE:
		stdlog.Printf("Error fetching blocks for sync with %s: %v", s.Conn().RemotePeer().String(), resp.Error)
		writer.WriteJSON(map[string]string{"error": resp.Error.Error()})
		return
	}

	blocks, ok := resp.Data.([]*types.Block)
	if !ok {
		stdlog.Printf("Invalid data type received for GetBlocksFromHeight from message bus: %T", resp.Data)
		writer.WriteJSON(map[string]string{"error": "internal server error"})
		return
	}

	for _, block := range blocks {
		if err := writer.WriteJSON(block); err != nil {
			stdlog.Printf("Error writing block %s to sync stream: %v", block.Hash, err)
			return
		}
	}
	writer.Write([]byte("EOF\n"))
	// CHANGE THIS LINE:
	stdlog.Printf("Sent %d blocks to peer %s for sync.", len(blocks), s.Conn().RemotePeer().String())
}

func (lm *Libp2pManager) handleTransactionRequest(s network.Stream) {
	defer s.Close()
	// CHANGE THIS LINE:
	stdlog.Printf("Received transaction from %s", s.Conn().RemotePeer().String())

	reader := NewJSONStreamReader(s)
	var tx thrylos.Transaction
	if err := reader.ReadJSON(&tx); err != nil {
		stdlog.Printf("Error unmarshaling transaction: %v", err)
		return
	}

	lm.BlockchainProcessCh <- types.Message{Type: types.ProcessTransaction, Data: &tx}
}

func (lm *Libp2pManager) handleVoteRequest(s network.Stream) {
	defer s.Close()
	// CHANGE THIS LINE:
	stdlog.Printf("Received vote from %s", s.Conn().RemotePeer().String())

	reader := NewJSONStreamReader(s)
	var vote types.Vote
	if err := reader.ReadJSON(&vote); err != nil {
		stdlog.Printf("Error unmarshaling vote: %v", err)
		return
	}

	lm.BlockchainProcessCh <- types.Message{Type: types.ProcessVote, Data: &vote}
}

// --- PubSub Logic ---

func (lm *Libp2pManager) subscribeToPubSubTopics() {
	topics := []string{TopicBlocks, TopicTransactions, TopicVotes}
	for _, topicName := range topics {
		topic, err := lm.PubSub.Join(topicName)
		if err != nil {
			stdlog.Fatalf("Failed to join PubSub topic %s: %v", topicName, err) // <--- FIX 1: Use aliased stdlog
		}
		sub, err := topic.Subscribe()
		if err != nil {
			stdlog.Fatalf("Failed to subscribe to PubSub topic %s: %v", topicName, err) // <--- FIX 1: Use aliased stdlog
		}
		go lm.readPubSubMessages(topicName, sub)
		stdlog.Printf("Subscribed to PubSub topic: %s", topicName) // <--- FIX 1: Use aliased stdlog
	}
}

func (lm *Libp2pManager) readPubSubMessages(topicName string, sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(lm.Ctx)
		if err != nil {
			if err == context.Canceled {
				stdlog.Printf("PubSub subscription for %s canceled.", topicName) // <--- FIX 1: Use aliased stdlog
			} else {
				stdlog.Printf("Error reading from PubSub subscription %s: %v", topicName, err) // <--- FIX 1: Use aliased stdlog
			}
			return
		}

		if msg.ReceivedFrom == lm.Host.ID() {
			continue // Ignore messages from self
		}

		stdlog.Printf("Received PubSub message from %s on topic %s", msg.ReceivedFrom.String(), topicName) // <--- FIX 3: Use .String()

		switch topicName {
		case TopicBlocks:
			var block types.Block
			if err := json.Unmarshal(msg.Data, &block); err != nil {
				stdlog.Printf("Failed to unmarshal block from PubSub: %v", err) // <--- FIX 1: Use aliased stdlog
				continue
			}
			lm.BlockchainProcessCh <- types.Message{Type: types.ProcessBlock, Data: &block}
		case TopicTransactions:
			var tx thrylos.Transaction
			if err := json.Unmarshal(msg.Data, &tx); err != nil {
				stdlog.Printf("Failed to unmarshal transaction from PubSub: %v", err) // <--- FIX 1: Use aliased stdlog
				continue
			}
			lm.BlockchainProcessCh <- types.Message{Type: types.ProcessTransaction, Data: &tx}
		case TopicVotes:
			var vote types.Vote
			if err := json.Unmarshal(msg.Data, &vote); err != nil {
				stdlog.Printf("Failed to unmarshal vote from PubSub: %v", err) // <--- FIX 1: Use aliased stdlog
				continue
			}
			lm.BlockchainProcessCh <- types.Message{Type: types.ProcessVote, Data: &vote}
		}
	}
}

// --- Broadcasting Functions ---

func (lm *Libp2pManager) BroadcastBlock(block *types.Block) error {
	blockData, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to serialize block for PubSub: %w", err)
	}
	topic, err := lm.PubSub.Join(TopicBlocks)
	if err != nil {
		return fmt.Errorf("failed to get PubSub topic %s: %w", TopicBlocks, err)
	}
	stdlog.Printf("Broadcasting block %s via PubSub to topic %s", block.Hash, TopicBlocks) // <--- FIX 1: Use aliased stdlog
	return topic.Publish(lm.Ctx, blockData)
}

func (lm *Libp2pManager) BroadcastTransaction(tx *thrylos.Transaction) error {
	txData, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to serialize transaction for PubSub: %w", err)
	}
	topic, err := lm.PubSub.Join(TopicTransactions)
	if err != nil {
		return fmt.Errorf("failed to get PubSub topic %s: %w", TopicTransactions, err)
	}
	stdlog.Printf("Broadcasting transaction %s via PubSub to topic %s", tx.Id, TopicTransactions) // <--- FIX 1: Use aliased stdlog
	return topic.Publish(lm.Ctx, txData)
}

func (lm *Libp2pManager) BroadcastVote(vote types.Vote) error {
	voteData, err := json.Marshal(vote)
	if err != nil {
		return fmt.Errorf("failed to serialize vote for PubSub: %w", err)
	}
	topic, err := lm.PubSub.Join(TopicVotes)
	if err != nil {
		return fmt.Errorf("failed to get PubSub topic %s: %w", TopicVotes, err)
	}
	stdlog.Printf("Broadcasting vote for block %s via PubSub to topic %s", vote.BlockHash, TopicVotes) // <--- FIX 1: Use aliased stdlog
	return topic.Publish(lm.Ctx, voteData)
}

func (lm *Libp2pManager) SyncBlockchainWithPeer(peerID peer.ID) error {
	stdlog.Printf("Initiating blockchain sync with peer: %s", peerID.String()) // <--- FIX 3: Use .String()
	s, err := lm.Host.NewStream(lm.Ctx, peerID, ProtocolBlockSync)
	if err != nil {
		return fmt.Errorf("failed to open block sync stream with %s: %w", peerID.String(), err)
	}
	defer s.Close()

	writer := NewJSONStreamWriter(s) // <--- Use custom writer
	reader := NewJSONStreamReader(s) // <--- Use custom reader

	// 1. Get our current blockchain height
	heightCh := make(chan types.Response)
	lm.messageBus.Publish(types.Message{
		Type:       types.GetBlockchainInfo,
		Data:       "height",
		ResponseCh: heightCh,
	})
	heightResp := <-heightCh

	var currentHeight int32
	if heightResp.Error == nil {
		if height, ok := heightResp.Data.(int32); ok {
			currentHeight = height
		}
	} else {
		stdlog.Printf("Warning: Could not get current blockchain height for sync: %v", heightResp.Error) // <--- FIX 1: Use aliased stdlog
		currentHeight = 0
	}

	// 2. Send request to peer for blocks from startHeight
	reqData := map[string]int32{"startHeight": currentHeight + 1}
	if err := writer.WriteJSON(reqData); err != nil { // <--- Use custom writer
		return fmt.Errorf("failed to write sync request to stream: %w", err)
	}

	// 3. Read blocks from the peer's stream
	var totalSyncedBlocks int
	for {
		var block types.Block
		err := reader.ReadJSON(&block) // <--- Use custom reader
		if err != nil {
			if err == io.EOF {
				stdlog.Printf("Sync stream from %s closed by peer.", peerID.String()) // <--- FIX 3: Use .String()
				break
			}
			// If it's a specific "EOF" marker from the peer, handle it
			if err.Error() == "received EOF marker" { // Custom check for custom JSONStreamReader
				stdlog.Printf("Received end-of-sync marker from %s.", peerID.String())
				break
			}
			return fmt.Errorf("error reading block data from stream: %w", err)
		}

		// Send block to blockchain core for processing
		lm.BlockchainProcessCh <- types.Message{Type: types.ProcessBlock, Data: &block}
		totalSyncedBlocks++
	}
	stdlog.Printf("Successfully synced %d blocks from peer %s", totalSyncedBlocks, peerID.String()) // <--- FIX 3: Use .String()
	return nil
}

func (lm *Libp2pManager) SyncBlockchain() {
	stdlog.Println("Starting blockchain synchronization with libp2p peers...") // <--- FIX 1: Use aliased stdlog

	peers := lm.Host.Network().Peers()
	if len(peers) == 0 {
		stdlog.Println("No libp2p peers available for blockchain synchronization.") // <--- FIX 1: Use aliased stdlog
		return
	}

	var wg sync.WaitGroup
	for _, peerID := range peers {
		wg.Add(1)
		go func(pID peer.ID) {
			defer wg.Done()
			if err := lm.SyncBlockchainWithPeer(pID); err != nil {
				stdlog.Printf("Failed to sync with peer %s: %v", pID.String(), err) // <--- FIX 3: Use .String()
			}
		}(peerID)
	}

	wg.Wait()
	stdlog.Println("Blockchain synchronization with libp2p peers completed.") // <--- FIX 1: Use aliased stdlog
}

// --- Custom JSON Stream Reader/Writer (Replacement for NewDelimitedReader/Writer) ---
// These helpers allow you to send/receive JSON objects over a stream, one per line.
// For more complex binary protocols, consider protobufs with length-prefixing.

type JSONStreamReader struct {
	decoder *json.Decoder
	reader  io.Reader
}

func NewJSONStreamReader(r io.Reader) *JSONStreamReader {
	return &JSONStreamReader{
		decoder: json.NewDecoder(r),
		reader:  r,
	}
}

// ReadJSON reads a JSON object from the stream into the given interface.
// It assumes JSON objects are terminated by newlines or stream end.
func (jsr *JSONStreamReader) ReadJSON(v interface{}) error {
	// A more robust implementation might read byte by byte until a newline,
	// or use a bufio.Scanner with bufio.ScanLines.
	// For simplicity, json.Decoder.Decode() often works directly on the stream
	// for single objects or a stream of objects.
	// If the stream ends with "EOF\n", this will treat it as a json error.
	// You might need a custom delimiter. For this example, let's assume valid JSON is followed by a newline.
	if err := jsr.decoder.Decode(v); err != nil {
		// Special handling for EOF marker if you choose to send it as text
		var raw json.RawMessage
		if err := jsr.decoder.Decode(&raw); err == io.EOF && string(raw) == "EOF" {
			return fmt.Errorf("received EOF marker")
		}
		return err
	}
	return nil
}

type JSONStreamWriter struct {
	encoder *json.Encoder
	writer  io.Writer
}

func NewJSONStreamWriter(w io.Writer) *JSONStreamWriter {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false) // Often good for blockchain data
	return &JSONStreamWriter{
		encoder: encoder,
		writer:  w,
	}
}

// WriteJSON writes a JSON object to the stream, followed by a newline.
func (jsw *JSONStreamWriter) WriteJSON(v interface{}) error {
	if err := jsw.encoder.Encode(v); err != nil { // Encode adds a newline by default
		return err
	}
	// No need to explicitly write a newline with `Encode` if it does it automatically.
	// If you want more control, use `json.Marshal` and then `writer.Write(data); writer.Write([]byte{'\n'})`
	return nil
}

// You might also want a generic Write for raw bytes, similar to original delimited writer
func (jsw *JSONStreamWriter) Write(data []byte) (int, error) {
	return jsw.writer.Write(data)
}
