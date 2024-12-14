package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/supabase-community/supabase-go"
)

func (n *Node) logError(stage string, err error) {
	log.Printf("[%s] error: %v", stage, err)
}

func publicKeyToBech32(pubKeyBase64 string) (string, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		log.Printf("Failed to decode base64 public key: %v", err)
		return "", err
	}

	data, err := bech32.ConvertBits(pubKeyBytes, 8, 5, true)
	if err != nil {
		log.Printf("Failed to convert bits for Bech32: %v", err)
		return "", err
	}

	bech32Address, err := bech32.Encode("tl1", data)
	if err != nil {
		log.Printf("Failed to encode Bech32 address: %v", err)
		return "", err
	}

	log.Printf("Generated Bech32 address: %s", bech32Address)
	return bech32Address, nil
}

func ThrylosTo(thrylos float64) int64 {
	return int64(thrylos)
}

func GetUsernameByUID(supabaseClient *supabase.Client, userID string) (string, error) {
	data, _, err := supabaseClient.From("users").
		Select("username", "exact", false).
		Eq("id", userID).
		Single().
		Execute()

	if err != nil {
		fmt.Println("Error executing username query:", err)
		return "", fmt.Errorf("error executing query: %v", err)
	}

	var result struct {
		Username string `json:"username"`
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		fmt.Println("Error unmarshaling username data:", err)
		return "", fmt.Errorf("username not found for user %s", userID)
	}

	return result.Username, nil
}

func GetBlockchainAddressByUID(supabaseClient *supabase.Client, userID string) (string, error) {
	data, _, err := supabaseClient.From("blockchain_info").
		Select("blockchain_address", "exact", false).
		Eq("user_id", userID).
		Single().
		Execute()

	if err != nil {
		fmt.Println("Error executing query:", err)
		return "", fmt.Errorf("error executing query: %v", err)
	}

	var result struct {
		PublicKeyBase64 string `json:"blockchain_address"`
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		fmt.Println("Error unmarshaling data:", err)
		return "", fmt.Errorf("public key not found for user %s", userID)
	}

	return result.PublicKeyBase64, nil
}

// Helper function to fetch gas estimate
func (n *Node) FetchGasEstimate(dataSize int, balance int64) (int, error) {
	url := fmt.Sprintf("%s?dataSize=%d&balance=%d", "https://node.thrylos.org/gas-fee", dataSize, balance)
	log.Printf("Fetching gas estimate from URL: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		log.Printf("HTTP request failed: %v", err)
		return 0, err
	}
	defer resp.Body.Close()

	log.Printf("Received response with status code: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to fetch gas estimate, status code: %d", resp.StatusCode)
		return 0, fmt.Errorf("failed to fetch gas estimate, status code: %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Error decoding JSON response: %v", err)
		return 0, err
	}

	log.Printf("Gas estimate received: %v", result)

	if gasFeeValue, exists := result["gasFee"]; exists {
		var gasEstimate int

		switch v := gasFeeValue.(type) {
		case float64:
			gasEstimate = int(v)
		case string:
			parsedValue, err := strconv.Atoi(v)
			if err != nil {
				log.Printf("Error parsing gas fee string: %v", err)
				return 0, fmt.Errorf("invalid gas fee format: %v", err)
			}
			gasEstimate = parsedValue
		default:
			log.Printf("Unexpected type for gas fee: %T", v)
			return 0, fmt.Errorf("unexpected gas fee type: %T", v)
		}

		log.Printf("Gas estimate found: %d (0.%06d THRYLOS)", gasEstimate, gasEstimate)
		return gasEstimate, nil
	} else {
		log.Printf("Gas estimate not found in the response: %v", result)
		return 0, fmt.Errorf("gas estimate not found in response")
	}
}

func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
