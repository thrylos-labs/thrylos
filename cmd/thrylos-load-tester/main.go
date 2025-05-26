package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	thrylosCrypto "github.com/thrylos-labs/thrylos/crypto"
)

// --- TestAccount, JsonRpcPayload, PrepareTxResponseResult, JsonRpcResponseWrapper structs ---
// --- (Copy these from the previous response where they were defined) ---
type TestAccount struct {
	AddressStr string
	ThrylosPK  thrylosCrypto.PublicKey
	ThrylosSK  thrylosCrypto.PrivateKey
}

type JsonRpcPayload struct {
	JsonRpc string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      interface{}   `json:"id"`
}

type PrepareTxResponseResult struct {
	TxID                   string `json:"txId"`
	CanonicalPayloadString string `json:"canonicalPayloadString"`
	Message                string `json:"message"`
}

type JsonRpcResponseWrapper struct {
	JsonRpc string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   interface{}     `json:"error,omitempty"`
	ID      interface{}     `json:"id"`
}

// --- newLoadGeneratorTestAccount function ---
// --- (Copy from the previous response) ---
func newLoadGeneratorTestAccount() (*TestAccount, error) {
	rawMldsaPK, rawMldsaSK, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mldsa44 keys: %w", err)
	}
	if rawMldsaPK == nil || rawMldsaSK == nil {
		return nil, fmt.Errorf("mldsa44.GenerateKey returned nil key(s)")
	}
	thrylosSK := thrylosCrypto.NewPrivateKeyFromMLDSA(rawMldsaSK)
	if thrylosSK == nil {
		return nil, fmt.Errorf("thrylosCrypto.NewPrivateKeyFromMLDSA returned nil for private key")
	}
	thrylosPK := thrylosSK.PublicKey()
	if thrylosPK == nil {
		return nil, fmt.Errorf("thrylosSK.PublicKey() returned nil")
	}
	addrObj, err := thrylosPK.Address()
	if err != nil {
		return nil, fmt.Errorf("could not get address object from thrylos public key: %w", err)
	}
	if addrObj == nil {
		return nil, fmt.Errorf("thrylosPK.Address() returned a nil address object")
	}
	addressStr := addrObj.String()
	if addressStr == "" {
		return nil, fmt.Errorf("derived empty address string (check logs for encoding errors)")
	}
	// log.Printf("DEBUG: Generated new test account. Thrylos Address: %s", addressStr)
	return &TestAccount{
		AddressStr: addressStr,
		ThrylosPK:  thrylosPK,
		ThrylosSK:  thrylosSK,
	}, nil
}

// --- LoadGenerator struct ---
type LoadGenerator struct {
	nodeURL        string
	httpClient     *http.Client
	accounts       []*TestAccount
	faucetAccount  *TestAccount // Account with initial large funds
	targetTPS      int
	duration       time.Duration
	numWorkers     int
	requestCounter uint64 // Atomic counter for unique request IDs
}

// --- executeTransaction method (modified to be part of LoadGenerator) ---
// --- (Copy from the previous response, ensure it's a method of *LoadGenerator) ---
func (g *LoadGenerator) executeTransaction(sender *TestAccount, recipientAddress string, amountNano int64) (string, error) {
	// Increment request ID counter atomically for each RPC call
	prepRequestID := atomic.AddUint64(&g.requestCounter, 1)
	submitRequestID := atomic.AddUint64(&g.requestCounter, 1)

	// 1. Prepare Transaction
	thrylosPkBytes := sender.ThrylosPK.Bytes()
	if thrylosPkBytes == nil {
		return "", fmt.Errorf("failed to get bytes from sender.ThrylosPK, it's nil or its underlying key is nil")
	}
	pubKeyBase64 := base64.StdEncoding.EncodeToString(thrylosPkBytes)

	prepParams := map[string]interface{}{
		"sender":     sender.AddressStr,
		"recipient":  recipientAddress,
		"amountNano": float64(amountNano),
		"publicKey":  pubKeyBase64,
	}
	rpcReq := JsonRpcPayload{
		JsonRpc: "2.0",
		Method:  "prepareTransaction",
		Params:  []interface{}{prepParams},
		ID:      prepRequestID,
	}
	reqBody, err := json.Marshal(rpcReq)
	if err != nil {
		return "", fmt.Errorf("marshal prep: %w", err)
	}
	httpResp, err := g.httpClient.Post(g.nodeURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("post prep: %w", err)
	}
	defer httpResp.Body.Close()
	respBodyBytes, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return "", fmt.Errorf("read prep body: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("prep API err %s: %s", httpResp.Status, string(respBodyBytes))
	}
	var rpcResp JsonRpcResponseWrapper
	if err := json.Unmarshal(respBodyBytes, &rpcResp); err != nil {
		return "", fmt.Errorf("unmarshal prep resp: %w. Body: %s", err, string(respBodyBytes))
	}
	if rpcResp.Error != nil {
		return "", fmt.Errorf("prep RPC err: %+v", rpcResp.Error)
	}
	if rpcResp.Result == nil {
		return "", fmt.Errorf("prep RPC res nil. Body: %s", string(respBodyBytes))
	}
	var prepResult PrepareTxResponseResult
	if err := json.Unmarshal(rpcResp.Result, &prepResult); err != nil {
		return "", fmt.Errorf("unmarshal prep res: %w. Raw: %s", err, string(rpcResp.Result))
	}
	txID := prepResult.TxID
	canonicalPayloadBase64 := prepResult.CanonicalPayloadString

	// 2. Sign Transaction
	rawCanonicalPayload, err := base64.StdEncoding.DecodeString(canonicalPayloadBase64)
	if err != nil {
		return txID, fmt.Errorf("decode canonical for %s: %w", txID, err)
	}
	thrylosSignatureObject := sender.ThrylosSK.Sign(rawCanonicalPayload)
	if thrylosSignatureObject == nil {
		return txID, fmt.Errorf("Sign nil for %s", txID)
	}
	signatureBytes := thrylosSignatureObject.Bytes()
	if signatureBytes == nil {
		return txID, fmt.Errorf("SigBytes nil for %s", txID)
	}
	signatureBase64 := base64.StdEncoding.EncodeToString(signatureBytes)

	// 3. Submit Signed Transaction
	submitParams := map[string]interface{}{
		"txId": txID, "signature": signatureBase64, "publicKey": pubKeyBase64, "canonicalPayloadString": canonicalPayloadBase64,
	}
	rpcSubmitReq := JsonRpcPayload{
		JsonRpc: "2.0", Method: "submitSignedTransaction", Params: []interface{}{submitParams}, ID: submitRequestID,
	}
	reqSubmitBody, err := json.Marshal(rpcSubmitReq)
	if err != nil {
		return txID, fmt.Errorf("marshal submit for %s: %w", txID, err)
	}
	submitHttpResp, err := g.httpClient.Post(g.nodeURL, "application/json", bytes.NewBuffer(reqSubmitBody))
	if err != nil {
		return txID, fmt.Errorf("post submit for %s: %w", txID, err)
	}
	defer submitHttpResp.Body.Close()
	submitRespBodyBytes, err := ioutil.ReadAll(submitHttpResp.Body)
	if err != nil {
		return txID, fmt.Errorf("read submit body for %s: %w", txID, err)
	}
	if submitHttpResp.StatusCode != http.StatusOK {
		return txID, fmt.Errorf("submit API err for %s %s: %s", txID, submitHttpResp.Status, string(submitRespBodyBytes))
	}
	var rpcSubmitResp JsonRpcResponseWrapper
	if err := json.Unmarshal(submitRespBodyBytes, &rpcSubmitResp); err != nil {
		return txID, fmt.Errorf("unmarshal submit for %s: %w. Body: %s", txID, err, string(submitRespBodyBytes))
	}
	if rpcSubmitResp.Error != nil {
		return txID, fmt.Errorf("submit RPC for %s err: %+v", txID, rpcSubmitResp.Error)
	}
	return txID, nil
}

func (g *LoadGenerator) fundWorkerAccounts(numAccounts int, amountPerAccount int64) error {
	log.Printf("Funding %d worker accounts with %d nanoTHR each from faucet %s...", numAccounts, amountPerAccount, g.faucetAccount.AddressStr)
	g.accounts = make([]*TestAccount, numAccounts)
	for i := 0; i < numAccounts; i++ {
		acc, err := newLoadGeneratorTestAccount()
		if err != nil {
			return fmt.Errorf("failed to create worker account %d: %w", i, err)
		}
		g.accounts[i] = acc
		log.Printf("Funding account %s...", acc.AddressStr)
		_, err = g.executeTransaction(g.faucetAccount, acc.AddressStr, amountPerAccount)
		if err != nil {
			// Consider retries or handling this more gracefully
			log.Printf("WARNING: Failed to fund account %s: %v. This account might not be usable.", acc.AddressStr, err)
		} else {
			log.Printf("Successfully submitted funding transaction for %s", acc.AddressStr)
		}
		// In a real scenario, wait for confirmation or add a delay
		time.Sleep(100 * time.Millisecond) // Simple delay
	}
	log.Println("Worker account funding process completed. Please wait for transactions to be included in blocks.")
	// It's crucial to wait here for funding transactions to confirm before starting the main load test.
	// This might involve polling balances or waiting a fixed duration.
	time.Sleep(20 * time.Second) // Example: Wait for a couple of block times
	return nil
}

func (g *LoadGenerator) worker(wg *sync.WaitGroup, successCount *uint64, errorCount *uint64, stopCh <-chan struct{}, workerID int) {
	defer wg.Done()
	accountIndex := workerID % len(g.accounts) // Assign an account to this worker
	senderAccount := g.accounts[accountIndex]
	recipientAccount := g.accounts[(workerID+1)%len(g.accounts)] // Send to another worker's account

	if senderAccount.AddressStr == recipientAccount.AddressStr && len(g.accounts) > 1 {
		recipientAccount = g.accounts[(workerID+2)%len(g.accounts)] // Try to avoid sending to self if possible
	}
	if senderAccount.AddressStr == recipientAccount.AddressStr {
		log.Printf("Worker %d: Warning - sender and recipient are the same: %s", workerID, senderAccount.AddressStr)
	}

	log.Printf("Worker %d started, using sender %s, recipient %s", workerID, senderAccount.AddressStr, recipientAccount.AddressStr)

	// Simple rate limiting: calculate delay to achieve targetTPS per worker
	var delay time.Duration
	if g.targetTPS > 0 && g.numWorkers > 0 {
		tpsPerWorker := float64(g.targetTPS) / float64(g.numWorkers)
		if tpsPerWorker > 0 {
			delay = time.Duration(float64(time.Second) / tpsPerWorker)
		}
	}

	for {
		select {
		case <-stopCh:
			log.Printf("Worker %d stopping.", workerID)
			return
		default:
			_, err := g.executeTransaction(senderAccount, recipientAccount.AddressStr, 1000000) // Send 0.1 THR
			if err != nil {
				atomic.AddUint64(errorCount, 1)
				log.Printf("Worker %d - ERROR: %v", workerID, err)
			} else {
				atomic.AddUint64(successCount, 1)
			}
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}
}

func main() {
	nodeURL := flag.String("node-url", "http://localhost:50051", "Blockchain node RPC URL")
	workers := flag.Int("workers", 10, "Number of concurrent workers")
	durationStr := flag.String("duration", "30s", "Test duration (e.g., 30s, 1m, 1h)")
	targetTPS := flag.Int("tps", 100, "Target total transactions per second (0 for max speed)")
	faucetSeedHex := flag.String("faucet-seed", "", "Hex encoded seed for the faucet private key (must be pre-funded)") // Example: 64 hex chars
	numFundAccounts := flag.Int("fund-accounts", 20, "Number of worker accounts to create and fund")
	amountPerAccount := flag.Int64("fund-amount", 1000000000, "Amount in nanoTHR to fund each worker account (e.g., 100 THR)")

	flag.Parse()

	duration, err := time.ParseDuration(*durationStr)
	if err != nil {
		log.Fatalf("Invalid duration: %v", err)
	}

	if *faucetSeedHex == "" {
		log.Fatalf("-faucet-seed is required.")
	}
	seedBytes, err := hex.DecodeString(*faucetSeedHex) // Or your preferred decoding
	if err != nil {
		log.Fatalf("Invalid faucet seed hex format: %v", err)
	}

	if len(seedBytes) != mldsa44.SeedSize { // mldsa44.SeedSize is usually 32
		log.Fatalf("Faucet seed must be %d bytes long, got %d", mldsa44.SeedSize, len(seedBytes))
	}

	// Convert seedBytes ([]byte) to *[32]byte for NewKeyFromSeed
	var faucetSeedArray [mldsa44.SeedSize]byte
	copy(faucetSeedArray[:], seedBytes)

	// mldsa44.NewKeyFromSeed returns (*mldsa44.PublicKey, *mldsa44.PrivateKey)
	// There is no error returned by NewKeyFromSeed directly.
	rawMldsaFaucetPK, rawMldsaFaucetSK := mldsa44.NewKeyFromSeed(&faucetSeedArray) // Pass pointer to the array

	// It's good practice to check if the returned keys are nil,
	// although with a correctly sized seed, they generally shouldn't be.
	if rawMldsaFaucetPK == nil || rawMldsaFaucetSK == nil {
		log.Fatalf("Failed to create faucet key from seed; NewKeyFromSeed returned nil key(s).")
	}

	faucetThrylosSK := thrylosCrypto.NewPrivateKeyFromMLDSA(rawMldsaFaucetSK)
	if faucetThrylosSK == nil {
		log.Fatalf("Failed to create faucet Thrylos SK from mldsa SK")
	}
	faucetThrylosPK := faucetThrylosSK.PublicKey()
	if faucetThrylosPK == nil {
		log.Fatalf("Failed to get faucet Thrylos PK from Thrylos SK")
	}
	faucetAddrObj, err := faucetThrylosPK.Address() // Assuming .Address() can return an error
	if err != nil {
		log.Fatalf("Failed to get faucet address object: %v", err)
	}
	faucetAddressStr := faucetAddrObj.String()
	if faucetAddressStr == "" {
		log.Fatalf("Generated empty faucet address string.")
	}

	generator := &LoadGenerator{
		nodeURL:    *nodeURL,
		httpClient: &http.Client{Timeout: 20 * time.Second},
		faucetAccount: &TestAccount{ // Assign the correctly created faucet account
			AddressStr: faucetAddressStr,
			ThrylosPK:  faucetThrylosPK,
			ThrylosSK:  faucetThrylosSK,
		},
		targetTPS:  *targetTPS,
		duration:   duration,
		numWorkers: *workers,
	}

	// Fund worker accounts
	if err := generator.fundWorkerAccounts(*numFundAccounts, *amountPerAccount); err != nil {
		log.Fatalf("Failed to fund worker accounts: %v", err)
	}
	if len(generator.accounts) == 0 {
		log.Fatalf("No worker accounts available after funding. Check funding process and node logs.")
	}
	if *workers > len(generator.accounts) {
		log.Printf("Warning: Number of workers (%d) is greater than funded accounts (%d). Some workers will reuse accounts.", *workers, len(generator.accounts))
		// You might want to cap workers to numFundAccounts or handle account assignment more dynamically
	}

	log.Printf("Starting TPS test: %d workers, duration %s, target TPS %d, node %s",
		generator.numWorkers, generator.duration, generator.targetTPS, generator.nodeURL)

	var successCount uint64
	var errorCount uint64
	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	startTime := time.Now()

	for i := 0; i < generator.numWorkers; i++ {
		wg.Add(1)
		go generator.worker(&wg, &successCount, &errorCount, stopCh, i)
	}

	time.Sleep(generator.duration)
	close(stopCh)
	wg.Wait()

	elapsed := time.Since(startTime)
	actualTPS := float64(successCount) / elapsed.Seconds()

	log.Printf("Test finished. Duration: %s", elapsed.Round(time.Millisecond))
	log.Printf("Total Transactions Attempted: %d", successCount+errorCount)
	log.Printf("Successful Transactions: %d", successCount)
	log.Printf("Failed Transactions: %d", errorCount)
	log.Printf("Actual TPS: %.2f", actualTPS)
}
