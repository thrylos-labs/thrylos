package core

import (
	"math"
	"time"
)

// NetworkMetrics represents the current state of the network
type NetworkMetrics struct {
	TransactionVolume int
	NodeCount         int
	AverageLatency    time.Duration
}

// ConsensusMethod represents different consensus algorithms
type ConsensusMethod int

const (
	ProofOfStake ConsensusMethod = iota
	DelegatedProofOfStake
	PracticalByzantineFailureTolerance
)

// TOBManager manages the Temporal-Optimized Blockchain functionality
type TOBManager struct {
	CurrentMetrics     NetworkMetrics
	PredictedMetrics   NetworkMetrics
	CurrentConsensus   ConsensusMethod
	PredictionModel    *ExponentialSmoothingModel
	OptimizationNeeded bool
}

// ExponentialSmoothingModel implements a simple prediction model
type ExponentialSmoothingModel struct {
	Alpha           float64 // Smoothing factor
	LastPrediction  NetworkMetrics
	LastObservation NetworkMetrics
}

// NewTOBManager creates and initializes a new TOBManager
func NewTOBManager(alpha float64) *TOBManager {
	return &TOBManager{
		PredictionModel:  NewExponentialSmoothingModel(alpha),
		CurrentConsensus: ProofOfStake, // Default consensus method
	}
}

// NewExponentialSmoothingModel creates a new prediction model
func NewExponentialSmoothingModel(alpha float64) *ExponentialSmoothingModel {
	return &ExponentialSmoothingModel{
		Alpha: alpha,
	}
}

// Update updates the prediction model with new observations
func (model *ExponentialSmoothingModel) Update(observation NetworkMetrics) {
	if model.LastObservation == (NetworkMetrics{}) {
		model.LastPrediction = observation
		model.LastObservation = observation
		return
	}

	model.LastPrediction = NetworkMetrics{
		TransactionVolume: int(model.Alpha*float64(observation.TransactionVolume) + (1-model.Alpha)*float64(model.LastPrediction.TransactionVolume)),
		NodeCount:         int(model.Alpha*float64(observation.NodeCount) + (1-model.Alpha)*float64(model.LastPrediction.NodeCount)),
		AverageLatency:    time.Duration(model.Alpha*float64(observation.AverageLatency) + (1-model.Alpha)*float64(model.LastPrediction.AverageLatency)),
	}

	model.LastObservation = observation
}

// Predict returns the predicted network metrics
func (model *ExponentialSmoothingModel) Predict() NetworkMetrics {
	return model.LastPrediction
}

// UpdateNetworkConditions updates the current network metrics and makes a prediction
func (tob *TOBManager) UpdateNetworkConditions(currentMetrics NetworkMetrics) {
	tob.CurrentMetrics = currentMetrics
	tob.PredictionModel.Update(currentMetrics)
	tob.PredictedMetrics = tob.PredictionModel.Predict()
	tob.OptimizationNeeded = tob.needsOptimization()
}

// needsOptimization determines if the consensus method needs to be optimized
func (tob *TOBManager) needsOptimization() bool {
	transactionVolumeThreshold := 100
	nodeCountThreshold := 10
	latencyThreshold := 500 * time.Millisecond

	return math.Abs(float64(tob.PredictedMetrics.TransactionVolume-tob.CurrentMetrics.TransactionVolume)) > float64(transactionVolumeThreshold) ||
		math.Abs(float64(tob.PredictedMetrics.NodeCount-tob.CurrentMetrics.NodeCount)) > float64(nodeCountThreshold) ||
		math.Abs(float64(tob.PredictedMetrics.AverageLatency-tob.CurrentMetrics.AverageLatency)) > float64(latencyThreshold)
}

// OptimizeConsensus determines the best consensus method based on predicted conditions
func (tob *TOBManager) OptimizeConsensus() ConsensusMethod {
	if tob.PredictedMetrics.TransactionVolume > 1000 && tob.PredictedMetrics.NodeCount > 100 {
		return PracticalByzantineFailureTolerance
	} else if tob.PredictedMetrics.TransactionVolume > 500 || tob.PredictedMetrics.NodeCount > 50 {
		return DelegatedProofOfStake
	}
	return ProofOfStake
}

// GetOptimalConsensus returns the optimal consensus method if optimization is needed
func (tob *TOBManager) GetOptimalConsensus() (ConsensusMethod, bool) {
	if tob.OptimizationNeeded {
		return tob.OptimizeConsensus(), true
	}
	return tob.CurrentConsensus, false
}
