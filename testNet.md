To run the testnet in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/thrylosnode

Then run the encryption: 
export AES_KEY_ENV_VAR='b8Eq7a0EWz06Ova4VNRN8ad6TkzCZkxNXm926rtNM2I='

By starting with new addresses, you can test how the system handles initialization, empty blocks, new transactions, and other edge cases more effectively.

then:
go run main.go --address=localhost:8080 --data=./node_data --testnet

Update the secure_accounts.json with the new addresses and info from the testnet

To run the cli signer to sign the transactions in terminal type:

Navigate to the directory containing your main.go using: 
cd cmd/clisigner

Sign the transaction: 

go run cli_signer.go -address="1a1c45b4b5b8ac712a8e03ac8d73f70659414a1017e4a6df0e6b4c40353e56a2" -transaction='{"sender": "1a1c45b4b5b8ac712a8e03ac8d73f70659414a1017e4a6df0e6b4c40353e56a2", "recipient": "33c5cb2862568a9b75997538af3b1c77a2f75c47fd99ebef99226e3da608192a", "amount": 100}'


Retreive the public key first:

 Before attempting another transaction submission, directly test the retrieval function for the public key in your code to confirm that it can indeed find and return the correct key. This can help isolate the issue:


Sugmit the transaction using Curl:

curl -X POST -H "Content-Type: application/json" -d '{
    "sender": "1a1c45b4b5b8ac712a8e03ac8d73f70659414a1017e4a6df0e6b4c40353e56a2",
    "recipient": "1a1c45b4b5b8ac712a8e03ac8d73f70659414a1017e4a6df0e6b4c40353e56a2",
    "amount": 100,
    "signature": "55qEsDuiChWA66Cyiq72FxBf5NWhnMTB0a4LXff2NKnzlEq1c/TFMdYXBTjT3QwfCWJ0Cs/XcRQhHP1OepbdDw==",
    "inputs": [
        {
            "transactionId": "genesis_1a1c45b4b5b8ac712a8e03ac8d73f70659414a1017e4a6df0e6b4c40353e56a2",
            "outputIndex": 0,
            "signature": "gUlqrDliv6vDiFt4JfB6HkNpPsLoFtoKwHnZJdIWRpDBF1qT5fij8ufksqHvad+k26MaPPxv5i1nz7DtezreCg=="
        }
    ]
}' http://localhost:8080/submit-transaction



Summary
Generate Transaction Data: Define the essential attributes of your transaction, like sender, recipient, and amount.
Sign the Transaction: Use your CLI utility to sign the transaction data, generating a digital signature.
Submit the Transaction: Send the signed transaction to your blockchain network for processing.



curl -X POST http://localhost:8080/submit-transaction \
-H "Content-Type: application/json" \
-d '{
    "inputs": [
        {
            "previousTx": "abcd1234",  # Replace with the actual transaction ID from your blockchain
            "index": 0,
            "signature": "OerEAtzxvz6Lpp3BUqhIpjGPmWRfrQ39hsyi+rk+C2EChXQvFPshbrXSIWnu5soDgle3yem8LGe6mRrx4nZGCQ=="  
        }
    ],
    "outputs": [
        {
            "amount": 100,
            "address": "276b3b8a5fa2e9bfba6c9c535440e13906ba2ad0aa45e8ffea398cd13f564515"
        }
    ],
    "sender": "83bd6c7abd525db141737207aa170c539581b57685158512e6ca78da463bf801",
    "recipient": "276b3b8a5fa2e9bfba6c9c535440e13906ba2ad0aa45e8ffea398cd13f564515",
    "amount": 100,
    "signature": "OerEAtzxvz6Lpp3BUqhIpjGPmWRfrQ39hsyi+rk+C2EChXQvFPshbrXSIWnu5soDgle3yem8LGe6mRrx4nZGCQ=="  
}