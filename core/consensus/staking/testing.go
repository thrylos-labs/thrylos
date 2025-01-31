package staking

func (s *StakingService) CreateStakeForTest(userAddress string, isDelegator bool, amount int64, timestamp int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.createStakeInternal(userAddress, isDelegator, amount, timestamp)
	return err
}

func (s *StakingService) UnstakeTokensForTest(userAddress string, isDelegator bool, amount int64, timestamp int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unstakeTokensInternal(userAddress, isDelegator, amount, timestamp)
}
