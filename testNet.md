To run the testnet in terminal type:

Navigate to the directory containing your main.go using 'cd cmd/thrylosnode'

Then run: go run main.go --address=localhost:8080 --data=./node_data --testnet

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
