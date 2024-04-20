To run the testnet in terminal type:

Navigate to the directory containing your main.go using 'cd cmd/thrylosnode'
Then run: export AES_KEY_ENV_VAR='b8Eq7a0EWz06Ova4VNRN8ad6TkzCZkxNXm926rtNM2I='

then: go run main.go --address=localhost:8080 --data=./node_data --testnet

To run the cli signer to sign the transactions in terminal type:

Navigate to the directory containing your main.go using 'cd cmd/clisigner'

Sign the transaction: go run cli_signer.go -address="9186c36a4d7ce8fd063c59adf4b0b42e1d5e0e3907c944cd99fd07cf4d00049c" -transaction='{"sender": "9186c36a4d7ce8fd063c59adf4b0b42e1d5e0e3907c944cd99fd07cf4d00049c", "recipient": "87cb32f5cacb03d4ed9cb41ad3fe3b316ae021d5afc2ee461786eb740a102b7e", "amount": 100}'






Sugmit the transaction using Curl:

curl -X POST http://localhost:8080/submit-transaction \
-H "Content-Type: application/json" \
-d '{
  "inputs": [
    {
      "previousTx": "0000000000000000000000000000000000000000000000000000000000000000",
      "index": 0,
      "signature": "<actual_signature_from_cli>",
      "ownerAddress": "9186c36a4d7ce8fd063c59adf4b0b42e1d5e0e3907c944cd99fd07cf4d00049c"
    }
  ],
  "outputs": [
    {
      "amount": 100,
      "address": "87cb32f5cacb03d4ed9cb41ad3fe3b316ae021d5afc2ee461786eb740a102b7e"
    }
  ]
}'

Summary
Generate Transaction Data: Define the essential attributes of your transaction, like sender, recipient, and amount.
Sign the Transaction: Use your CLI utility to sign the transaction data, generating a digital signature.
Submit the Transaction: Send the signed transaction to your blockchain network for processing.



curl -X POST http://localhost:8080/submit-transaction \
-H "Content-Type: application/json" \
-d '{
  "inputs": [
    {
      "previousTx": "0000000000000000000000000000000000000000000000000000000000000000",
      "index": 0,
      "signature": "test_signature",
      "ownerAddress": "5d736a7b5896d873cc640f729b7b14e38dabc568de075e309efb97ac0cff2570"
    }
  ],
  "outputs": [
    {
      "amount": 100,
      "address": "e66308a7b7cd63c73c99ea6e9939318667916f83664eafb143b3044f80a591bd"
    }
  ]
}'
