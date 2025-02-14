package store

// func (s *store) SaveValidator(v *types.Validator) error {
// 	addr := (*v).Address()
// 	data, err := (*v).Marshal()
// 	if err != nil {
// 		log.Printf("Error marshalling validator: %v\n", err)
// 		return err
// 	}
// 	key := []byte(ValidatorPrefix + addr.String())
// 	return s.db.Set(key, data)
// }

// func (s *store) GetValidator(addr address.Address) (*types.Validator, error) {
// 	var validatorData []byte
// 	db := s.db.GetDB()

// 	err := db.View(func(txn *badger.Txn) error {
// 		key := []byte(ValidatorPrefix + addr.String())
// 		log.Printf("Retrieving validator data: %s, key: %s", addr.String(), key)
// 		item, err := txn.Get(key)
// 		if err != nil {
// 			log.Printf("Error validator data %s: %v", addr.String(), err)
// 			return err
// 		}
// 		validatorData, err = item.ValueCopy(nil)
// 		return err
// 	})

// 	if err != nil {
// 		if err == badger.ErrKeyNotFound {
// 			log.Printf("Public key not found for validator %s", addr.String())
// 			return nil, fmt.Errorf("public key not found for validator %s", addr.String())
// 		}
// 		log.Printf("Error retrieving public key for validator %s: %v", addr.String(), err)
// 		return nil, fmt.Errorf("error retrieving public key for validator %s: %v", addr.String(), err)
// 	}

// 	v := validator.NewValidatorFromBytes(validatorData)
// 	return &v, nil
// }

// // ValidatorKeyStoreImpl implements the shared.ValidatorKeyStore interface
// type ValidatorKeyStoreImpl struct {
// 	keys          map[string]*mldsa44.PrivateKey
// 	mu            sync.RWMutex
// 	db            *Database
// 	encryptionKey []byte
// }

// // NewValidatorKeyStore creates and initializes a new ValidatorKeyStore
// // In store/validator_store.go
// func NewValidatorKeyStore(db *Database, encryptionKey []byte) types.ValidatorKeyStore {
// 	return &ValidatorKeyStoreImpl{
// 		keys:          make(map[string]*mldsa44.PrivateKey),
// 		mu:            sync.RWMutex{},
// 		db:            db,
// 		encryptionKey: encryptionKey,
// 	}
// }

// // StoreKey stores a private key for a validator
// func (vks *ValidatorKeyStoreImpl) StoreKey(address string, key *mldsa44.PrivateKey) error {
// 	vks.mu.Lock()
// 	defer vks.mu.Unlock()
// 	vks.keys[address] = key
// 	// Persist to database
// 	return vks.db.Set([]byte("validator:"+address), key.Bytes())
// }

// // GetKey retrieves a private key for a validator
// func (vks *ValidatorKeyStoreImpl) GetKey(address string) (*mldsa44.PrivateKey, bool) {
// 	vks.mu.RLock()
// 	defer vks.mu.RUnlock()
// 	key, exists := vks.keys[address]
// 	return key, exists
// }

// // RemoveKey removes a private key for a validator
// func (vks *ValidatorKeyStoreImpl) RemoveKey(address string) error {
// 	vks.mu.Lock()
// 	defer vks.mu.Unlock()
// 	delete(vks.keys, address)
// 	return vks.db.Delete([]byte("validator:" + address))
// }

// // HasKey checks if a key exists for a validator
// func (vks *ValidatorKeyStoreImpl) HasKey(address string) bool {
// 	vks.mu.RLock()
// 	defer vks.mu.RUnlock()
// 	_, exists := vks.keys[address]
// 	return exists
// }

// // GetAllAddresses returns all addresses that have stored keys
// func (vks *ValidatorKeyStoreImpl) GetAllAddresses() []string {
// 	vks.mu.RLock()
// 	defer vks.mu.RUnlock()
// 	addresses := make([]string, 0, len(vks.keys))
// 	for addr := range vks.keys {
// 		addresses = append(addresses, addr)
// 	}
// 	return addresses
// }
