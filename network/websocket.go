package network

// type WebsocketImpl struct {
// 	*shared.WebSocketManager
// }

// func (m *WebSocketManager) handleWebSocketSubscription(w http.ResponseWriter, r *http.Request, params []interface{}) {
// 	if len(params) < 1 {
// 		return
// 	}

// 	subData, ok := params[0].(map[string]interface{})
// 	if !ok {
// 		return
// 	}

// 	sub := &Subscription{}
// 	subBytes, _ := json.Marshal(subData)
// 	if err := json.Unmarshal(subBytes, sub); err != nil {
// 		return
// 	}

// 	responseCh := make(chan shared.Response)

// 	switch sub.Type {
// 	case "balance":
// 		// Handle multiple addresses
// 		for _, addr := range sub.Addresses {
// 			shared.GetMessageBus().Publish(shared.Message{
// 				Type:       shared.GetBalance,
// 				Data:       shared.UTXORequest{Address: addr},
// 				ResponseCh: responseCh,
// 			})

// 			response := <-responseCh
// 			if response.Error != nil {
// 				log.Printf("Balance subscription error for address %s: %v", addr, response.Error)
// 				continue
// 			}
// 		}
// 	case "transactions":
// 		shared.GetMessageBus().Publish(shared.Message{
// 			Type:       shared.ProcessTransaction,
// 			Data:       sub,
// 			ResponseCh: responseCh,
// 		})
// 	case "blocks":
// 		shared.GetMessageBus().Publish(shared.Message{
// 			Type:       shared.ProcessBlock,
// 			Data:       sub,
// 			ResponseCh: responseCh,
// 		})
// 	}

// 	// Handle response if needed
// 	response := <-responseCh
// 	if response.Error != nil {
// 		log.Printf("Subscription error: %v", response.Error)
// 		return
// 	}
// }

// func (m *WebSocketManager) subscribeToBalance(sub *Subscription) {
// 	for _, address := range sub.Addresses {
// 		m.mutex.Lock()
// 		if conn, exists := m.connections[address]; exists {
// 			conn.subscriptions = append(conn.subscriptions, sub)
// 			// Send initial balance
// 			m.SendBalanceUpdate(address)
// 		}
// 		m.mutex.Unlock()
// 	}
// }

// // Add a proper close handler
// func (m *WebSocketManager) closeWebSocket(conn *WebSocketConnection, address string) {
// 	if conn == nil {
// 		return
// 	}

// 	m.mutex.Lock()
// 	defer m.mutex.Unlock()

// 	// Close the websocket connection
// 	if conn.ws != nil {
// 		conn.ws.WriteControl(
// 			websocket.CloseMessage,
// 			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
// 			time.Now().Add(writeWait),
// 		)
// 		conn.ws.Close()
// 		conn.ws = nil
// 	}

// 	// Clean up channels
// 	select {
// 	case <-conn.done:
// 	default:
// 		close(conn.done)
// 	}

// 	select {
// 	case <-conn.send:
// 	default:
// 		close(conn.send)
// 	}

// 	delete(m.connections, address)
// 	log.Printf("WebSocket connection closed for address: %s", address)
// }

// func (conn *WebSocketConnection) enqueueMessage(data []byte) {
// 	conn.queueMutex.Lock()
// 	defer conn.queueMutex.Unlock()

// 	// Remove old messages if queue is full
// 	if len(conn.messageQueue) >= messageQueueSize {
// 		// Remove oldest messages
// 		conn.messageQueue = conn.messageQueue[1:]
// 	}

// 	conn.messageQueue = append(conn.messageQueue, &MessageItem{
// 		data:    data,
// 		retries: 0,
// 		created: time.Now(),
// 	})
// }

// func (conn *WebSocketConnection) processQueue() error {
// 	conn.queueMutex.Lock()
// 	defer conn.queueMutex.Unlock()

// 	if len(conn.messageQueue) == 0 {
// 		return nil
// 	}

// 	var remainingMessages []*MessageItem

// 	for _, item := range conn.messageQueue {
// 		if item.retries >= maxRetryAttempts {
// 			// Log dropped message
// 			log.Printf("Dropping message after %d retry attempts", maxRetryAttempts)
// 			continue
// 		}

// 		err := conn.ws.WriteMessage(websocket.TextMessage, item.data)
// 		if err != nil {
// 			item.retries++
// 			remainingMessages = append(remainingMessages, item)
// 			log.Printf("Failed to send message, attempt %d/%d: %v",
// 				item.retries, maxRetryAttempts, err)
// 			time.Sleep(retryDelay)
// 			continue
// 		}
// 	}

// 	conn.messageQueue = remainingMessages
// 	return nil
// }

// func (m *WebSocketManager) handleWebSocketUnsubscription(w http.ResponseWriter, r *http.Request, params []interface{}) {
// 	if len(params) < 1 {
// 		return
// 	}

// 	unsubData, ok := params[0].(map[string]interface{})
// 	if !ok {
// 		return
// 	}

// 	// Unsubscribe request format
// 	type UnsubscribeRequest struct {
// 		Type      string   `json:"type"`
// 		Addresses []string `json:"addresses,omitempty"`
// 	}

// 	unsub := &UnsubscribeRequest{}
// 	unsubBytes, _ := json.Marshal(unsubData)
// 	if err := json.Unmarshal(unsubBytes, unsub); err != nil {
// 		return
// 	}

// 	switch unsub.Type {
// 	case "balance":
// 		m.unsubscribeFromBalance(unsub.Addresses)
// 	case "transactions":
// 		m.unsubscribeFromTransactions(unsub.Addresses)
// 	case "blocks":
// 		m.unsubscribeFromBlocks(unsub.Addresses)
// 	}
// }

// func (m *WebSocketManager) unsubscribeFromBalance(addresses []string) {
// 	for _, address := range addresses {
// 		m.mutex.Lock()
// 		if conn, exists := m.connections[address]; exists {
// 			var remainingSubs []*Subscription
// 			for _, sub := range conn.subscriptions {
// 				if sub.Type != "balance" {
// 					remainingSubs = append(remainingSubs, sub)
// 				}
// 			}
// 			conn.subscriptions = remainingSubs

// 			// Notify through message bus
// 			responseCh := make(chan shared.Response)
// 			shared.GetMessageBus().Publish(shared.Message{
// 				Type: shared.UpdateState,
// 				Data: shared.UpdateStateRequest{
// 					Address: address,
// 				},
// 				ResponseCh: responseCh,
// 			})
// 		}
// 		m.mutex.Unlock()
// 	}
// }

// func (m *WebSocketManager) unsubscribeFromTransactions(addresses []string) {
// 	for _, address := range addresses {
// 		m.mutex.Lock()
// 		if conn, exists := m.connections[address]; exists {
// 			var remainingSubs []*Subscription
// 			for _, sub := range conn.subscriptions {
// 				if sub.Type != "transactions" {
// 					remainingSubs = append(remainingSubs, sub)
// 				}
// 			}
// 			conn.subscriptions = remainingSubs

// 			responseCh := make(chan shared.Response)
// 			shared.GetMessageBus().Publish(shared.Message{
// 				Type: shared.ProcessTransaction,
// 				Data: shared.UpdateProcessorStateRequest{
// 					TransactionID: address,
// 					State:         "unsubscribed",
// 				},
// 				ResponseCh: responseCh,
// 			})
// 		}
// 		m.mutex.Unlock()
// 	}
// }

// func (m *WebSocketManager) unsubscribeFromBlocks(addresses []string) {
// 	for _, address := range addresses {
// 		m.mutex.Lock()
// 		if conn, exists := m.connections[address]; exists {
// 			var remainingSubs []*Subscription
// 			for _, sub := range conn.subscriptions {
// 				if sub.Type != "blocks" {
// 					remainingSubs = append(remainingSubs, sub)
// 				}
// 			}
// 			conn.subscriptions = remainingSubs

// 			responseCh := make(chan shared.Response)
// 			shared.GetMessageBus().Publish(shared.Message{
// 				Type: shared.ProcessBlock,
// 				Data: shared.UpdateProcessorStateRequest{
// 					TransactionID: address,
// 					State:         "unsubscribed",
// 				},
// 				ResponseCh: responseCh,
// 			})
// 		}
// 		m.mutex.Unlock()
// 	}
// }

// // Add placeholder implementations for these methods
// func (m *WebSocketManager) subscribeToTransactions(sub *Subscription) {
// 	for _, address := range sub.Addresses {
// 		m.mutex.Lock()
// 		if conn, exists := m.connections[address]; exists {
// 			conn.subscriptions = append(conn.subscriptions, sub)

// 			responseCh := make(chan shared.Response)
// 			shared.GetMessageBus().Publish(shared.Message{
// 				Type: shared.ProcessTransaction,
// 				Data: shared.UpdateProcessorStateRequest{
// 					TransactionID: address,
// 					State:         "subscribed",
// 				},
// 				ResponseCh: responseCh,
// 			})
// 		}
// 		m.mutex.Unlock()
// 	}
// }

// func (m *WebSocketManager) subscribeToBlocks(sub *Subscription) {
// 	for _, address := range sub.Addresses {
// 		m.mutex.Lock()
// 		if conn, exists := m.connections[address]; exists {
// 			conn.subscriptions = append(conn.subscriptions, sub)

// 			responseCh := make(chan shared.Response)
// 			shared.GetMessageBus().Publish(shared.Message{
// 				Type: shared.ProcessBlock,
// 				Data: shared.UpdateProcessorStateRequest{
// 					TransactionID: address,
// 					State:         "subscribed",
// 				},
// 				ResponseCh: responseCh,
// 			})
// 		}
// 		m.mutex.Unlock()
// 	}
// }

// func NewWebSocketConnection(ws *websocket.Conn) *WebSocketConnection {
// 	return &WebSocketConnection{
// 		ws:              ws,
// 		send:            make(chan []byte, 256),
// 		reconnectCount:  0,
// 		lastConnectTime: time.Now(),
// 		isReconnecting:  false,
// 		done:            make(chan struct{}),
// 		subscriptions:   make([]*Subscription, 0),
// 		subscriptionID:  0,
// 		messageQueue:    make([]*MessageItem, 0),
// 	}
// }

// func (conn *WebSocketConnection) close() {
// 	if conn.ws != nil {
// 		// Send close message with normal closure status
// 		conn.ws.WriteControl(
// 			websocket.CloseMessage,
// 			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
// 			time.Now().Add(writeWait),
// 		)
// 		conn.ws.Close()
// 	}

// 	// Clean up channels
// 	select {
// 	case <-conn.done:
// 	default:
// 		close(conn.done)
// 	}
// }

// // Update message type for connection status
// func (m *WebSocketManager) handleReconnection(address string) {
// 	m.mutex.RLock()
// 	conn, exists := m.connections[address]
// 	m.mutex.RUnlock()

// 	if !exists || conn == nil {
// 		log.Printf("No valid connection found for address: %s", address)
// 		return
// 	}

// 	if conn.isReconnecting {
// 		log.Printf("Already attempting to reconnect for address: %s", address)
// 		return
// 	}

// 	if conn.reconnectCount >= maxReconnectAttempts {
// 		log.Printf("Max reconnection attempts reached for %s", address)
// 		m.closeWebSocket(conn, address)
// 		return
// 	}

// 	backoff := initialBackoff * time.Duration(1<<uint(conn.reconnectCount))
// 	if backoff > maxBackoff {
// 		backoff = maxBackoff
// 	}

// 	conn.reconnectCount++
// 	conn.isReconnecting = true

// 	log.Printf("Attempting to reconnect to %s in %v (attempt %d/%d)",
// 		address, backoff, conn.reconnectCount, maxReconnectAttempts)

// 	time.Sleep(backoff)

// 	// Notify about connection status
// 	responseCh := make(chan shared.Response)
// 	shared.GetMessageBus().Publish(shared.Message{
// 		Type: shared.UpdateState,
// 		Data: shared.UpdateStateRequest{
// 			Address: address,
// 			Balance: 0, // Use appropriate balance value if needed
// 		},
// 		ResponseCh: responseCh,
// 	})

// 	if err := m.reestablishConnection(address); err != nil {
// 		log.Printf("Reconnection failed for %s: %v", address, err)
// 		conn.isReconnecting = false
// 		go m.handleReconnection(address)
// 	} else {
// 		conn.reconnectCount = 0
// 		conn.isReconnecting = false
// 		conn.lastConnectTime = time.Now()
// 	}
// }

// func (m *WebSocketManager) reestablishConnection(address string) error {
// 	m.mutex.Lock()
// 	defer m.mutex.Unlock()

// 	conn, exists := m.connections[address]
// 	if !exists {
// 		return fmt.Errorf("no connection found for address: %s", address)
// 	}

// 	if conn.ws != nil {
// 		conn.close()
// 	}

// 	dialer := websocket.Dialer{
// 		HandshakeTimeout: 10 * time.Second,
// 		Subprotocols:     []string{"thrylos-protocol"},
// 	}

// 	header := http.Header{}
// 	header.Add("Origin", "http://localhost:3000")
// 	header.Add("Sec-WebSocket-Protocol", "thrylos-protocol")

// 	// Get server host through message bus
// 	responseCh := make(chan shared.Response)
// 	shared.GetMessageBus().Publish(shared.Message{
// 		Type:       shared.IsCounterNode,
// 		ResponseCh: responseCh,
// 	})
// 	response := <-responseCh

// 	serverHost, ok := response.Data.(string)
// 	if !ok {
// 		return fmt.Errorf("failed to get server host")
// 	}

// 	wsURL := fmt.Sprintf("ws://%s/ws/balance?address=%s", serverHost, address)
// 	ws, _, err := dialer.Dial(wsURL, header)
// 	if err != nil {
// 		return fmt.Errorf("failed to establish WebSocket connection: %v", err)
// 	}

// 	newConn := NewWebSocketConnection(ws)
// 	m.connections[address] = newConn

// 	go m.writePump(newConn, address)
// 	go m.readPump(newConn, address)

// 	return nil
// }

// // Configure the upgrader
// var upgrader = websocket.Upgrader{
// 	CheckOrigin: func(r *http.Request) bool {
// 		origin := r.Header.Get("Origin")
// 		allowedOrigins := []string{"http://localhost:3000", "https://node.thrylos.org"}

// 		for _, allowedOrigin := range allowedOrigins {
// 			if origin == allowedOrigin {
// 				return true
// 			}
// 		}
// 		return false
// 	},
// }

// func (m *WebSocketManager) WebSocketBalanceHandler(w http.ResponseWriter, r *http.Request) {
// 	log.Printf("Received WebSocket connection request for balance updates")

// 	address := r.URL.Query().Get("address")
// 	if address == "" {
// 		log.Println("Blockchain address is required")
// 		http.Error(w, "Blockchain address is required", http.StatusBadRequest)
// 		return
// 	}

// 	ws, err := m.upgrader.Upgrade(w, r, nil)
// 	if err != nil {
// 		log.Printf("Failed to upgrade to WebSocket: %v", err)
// 		http.Error(w, "WebSocket upgrade failed", http.StatusInternalServerError)
// 		return
// 	}

// 	m.mutex.Lock()
// 	if existingConn, exists := m.connections[address]; exists {
// 		if existingConn != nil {
// 			close(existingConn.done)
// 			if existingConn.ws != nil {
// 				existingConn.ws.Close()
// 			}
// 		}
// 		delete(m.connections, address)
// 	}

// 	conn := NewWebSocketConnection(ws)
// 	m.connections[address] = conn
// 	m.mutex.Unlock()

// 	go m.writePump(conn, address)
// 	go m.readPump(conn, address)

// 	// Send initial balance update using message bus
// 	responseCh := make(chan shared.Response)
// 	shared.GetMessageBus().Publish(shared.Message{
// 		Type: shared.GetBalance,
// 		Data: shared.UTXORequest{
// 			Address: address,
// 		},
// 		ResponseCh: responseCh,
// 	})

// 	response := <-responseCh
// 	if response.Error != nil {
// 		log.Printf("Error sending initial balance update for address %s: %v", address, response.Error)
// 	}
// }

// func (m *WebSocketManager) writePump(conn *WebSocketConnection, address string) {
// 	ticker := time.NewTicker(pingPeriod)
// 	defer func() {
// 		ticker.Stop()
// 		if !conn.isReconnecting {
// 			// Gracefully close before reconnecting
// 			conn.close()
// 			go m.handleReconnection(address)
// 		}
// 	}()

// 	for {
// 		select {
// 		case <-conn.done:
// 			return
// 		case message, ok := <-conn.send:
// 			if !ok {
// 				return
// 			}

// 			if err := conn.ws.WriteMessage(websocket.TextMessage, message); err != nil {
// 				log.Printf("Write error for %s: %v", address, err)
// 				return
// 			}

// 		case <-ticker.C:
// 			if err := conn.ws.WriteControl(
// 				websocket.PingMessage,
// 				[]byte{},
// 				time.Now().Add(writeWait),
// 			); err != nil {
// 				log.Printf("Ping error for %s: %v", address, err)
// 				return
// 			}
// 		}
// 	}
// }

// func (m *WebSocketManager) readPump(conn *WebSocketConnection, address string) {
// 	defer func() {
// 		m.mutex.Lock()
// 		delete(m.connections, address)
// 		m.mutex.Unlock()
// 		conn.ws.Close()
// 	}()

// 	conn.ws.SetReadLimit(maxMessageSize)
// 	conn.ws.SetReadDeadline(time.Now().Add(pongWait))
// 	conn.ws.SetPongHandler(func(string) error {
// 		conn.ws.SetReadDeadline(time.Now().Add(pongWait))
// 		return nil
// 	})

// 	for {
// 		_, message, err := conn.ws.ReadMessage()
// 		if err != nil {
// 			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
// 				log.Printf("WebSocket error: %v", err)
// 			}
// 			break
// 		}

// 		// Process message through message bus
// 		responseCh := make(chan shared.Response)
// 		shared.GetMessageBus().Publish(shared.Message{
// 			Type:       shared.ProcessTransaction,
// 			Data:       message,
// 			ResponseCh: responseCh,
// 		})

// 		response := <-responseCh
// 		if response.Error != nil {
// 			log.Printf("Error processing message from %s: %v", address, response.Error)
// 		}
// 	}
// }

// func (m *WebSocketManager) HandleBlockchainEvent(address string) {
// 	m.mutex.RLock()
// 	_, exists := m.connections[address]
// 	m.mutex.RUnlock()

// 	if exists {
// 		// Send balance update using message bus
// 		if err := m.SendBalanceUpdate(address); err != nil {
// 			log.Printf("Error sending balance update for address %s: %v", address, err)
// 		} else {
// 			log.Printf("Balance update sent for address %s", address)
// 		}
// 	}
// }

// // SendBalanceUpdate sends a balance update through the websocket
// // In your Go backend, modify SendBalanceUpdate:
// func (m *WebSocketManager) SendBalanceUpdate(address string) error {
// 	responseCh := make(chan shared.Response)
// 	shared.GetMessageBus().Publish(shared.Message{
// 		Type: shared.GetBalance,
// 		Data: shared.UTXORequest{
// 			Address: address,
// 		},
// 		ResponseCh: responseCh,
// 	})

// 	response := <-responseCh
// 	if response.Error != nil {
// 		return response.Error
// 	}

// 	balance, ok := response.Data.(int64)
// 	if !ok {
// 		return fmt.Errorf("invalid balance data type")
// 	}

// 	notification := map[string]interface{}{
// 		"jsonrpc": "2.0",
// 		"method":  "subscription",
// 		"params": map[string]interface{}{
// 			"subscription": "balance",
// 			"result": map[string]interface{}{
// 				"balance":        balance,
// 				"balanceThrylos": float64(balance) / 1e7,
// 			},
// 		},
// 	}

// 	messageBytes, err := json.Marshal(notification)
// 	if err != nil {
// 		return fmt.Errorf("failed to marshal message: %v", err)
// 	}

// 	m.mutex.RLock()
// 	defer m.mutex.RUnlock()

// 	if conn, exists := m.connections[address]; exists {
// 		return conn.ws.WriteMessage(websocket.TextMessage, messageBytes)
// 	}
// 	return fmt.Errorf("no WebSocket connection found for address: %s", address)
// }

// func (m *WebSocketManager) NotifyBalanceUpdate(address string, balance int64) {
// 	m.mutex.RLock()
// 	conn, exists := m.connections[address]
// 	m.mutex.RUnlock()

// 	if !exists || conn == nil {
// 		log.Printf("Address %s is offline - balance update will be received when they reconnect", address)
// 		return
// 	}

// 	balanceMsg := &thrylos.BalanceMessage{
// 		BlockchainAddress: address,
// 		Balance:           balance,
// 		BalanceThrylos:    float64(balance) / 1e7,
// 	}

// 	msgBytes, err := json.Marshal(balanceMsg)
// 	if err != nil {
// 		log.Printf("Error marshaling balance message for %s: %v", address, err)
// 		return
// 	}

// 	select {
// 	case conn.send <- msgBytes:
// 		log.Printf("Successfully sent balance update for %s: %d nanoTHRYLOS (%.7f THRYLOS)",
// 			address, balance, balanceMsg.BalanceThrylos)
// 	default:
// 		log.Printf("Channel full or closed for %s - balance update skipped", address)
// 	}
// }

// // Add the status endpoint handler
// func (m *WebSocketManager) WebSocketStatusHandler(w http.ResponseWriter, r *http.Request) {
// 	w.Header().Set("Content-Type", "application/json")
// 	w.Header().Set("Access-Control-Allow-Origin", "*")
// 	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
// 	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type")

// 	if r.Method == "OPTIONS" {
// 		w.WriteHeader(http.StatusOK)
// 		return
// 	}

// 	address := r.URL.Query().Get("address")
// 	if address == "" {
// 		w.WriteHeader(http.StatusBadRequest)
// 		json.NewEncoder(w).Encode(map[string]string{
// 			"error": "Address parameter is required",
// 		})
// 		return
// 	}

// 	m.mutex.RLock()
// 	conn, exists := m.connections[address]
// 	m.mutex.RUnlock()

// 	// Get balance through message bus
// 	responseCh := make(chan shared.Response)
// 	shared.GetMessageBus().Publish(shared.Message{
// 		Type: shared.GetBalance,
// 		Data: shared.UTXORequest{
// 			Address: address,
// 		},
// 		ResponseCh: responseCh,
// 	})

// 	response := <-responseCh
// 	var balance int64
// 	if response.Error != nil {
// 		log.Printf("Error getting balance for %s: %v", address, response.Error)
// 		balance = 0
// 	} else {
// 		balance, _ = response.Data.(int64)
// 	}

// 	balanceThrylos := float64(balance) / 1e7

// 	status := struct {
// 		Connected      bool      `json:"connected"`
// 		LastConnected  time.Time `json:"lastConnected"`
// 		ReconnectCount int       `json:"reconnectCount"`
// 		QueueSize      int       `json:"queueSize"`
// 		IsReconnecting bool      `json:"isReconnecting"`
// 		Balance        int64     `json:"balance"`
// 		BalanceThrylos float64   `json:"balanceThrylos"`
// 	}{
// 		Connected:      exists && conn != nil && conn.ws != nil,
// 		LastConnected:  time.Now(),
// 		ReconnectCount: 0,
// 		QueueSize:      0,
// 		IsReconnecting: false,
// 		Balance:        balance,
// 		BalanceThrylos: balanceThrylos,
// 	}

// 	if exists && conn != nil {
// 		status.ReconnectCount = conn.reconnectCount
// 		status.IsReconnecting = conn.isReconnecting
// 		status.LastConnected = conn.lastConnectTime
// 	}

// 	w.WriteHeader(http.StatusOK)
// 	if err := json.NewEncoder(w).Encode(status); err != nil {
// 		log.Printf("Error encoding status response: %v", err)
// 		w.WriteHeader(http.StatusInternalServerError)
// 		return
// 	}
// }
