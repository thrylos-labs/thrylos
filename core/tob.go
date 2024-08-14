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

// TOBManager manages the Temporal-Optimized Blockchain functionality
type TOBManager struct {
	CurrentMetrics     NetworkMetrics
	PredictedMetrics   NetworkMetrics
	PredictionModel    *ExponentialSmoothingModel
	OptimizationNeeded bool
	ConsensusManager   *ConsensusManager
}

// ExponentialSmoothingModel implements a simple prediction model
type ExponentialSmoothingModel struct {
	Alpha           float64 // Smoothing factor
	LastPrediction  NetworkMetrics
	LastObservation NetworkMetrics
}

// NewTOBManager creates and initializes a new TOBManager
func NewTOBManager(alpha float64, consensusManager *ConsensusManager) *TOBManager {
	return &TOBManager{
		PredictionModel:  NewExponentialSmoothingModel(alpha),
		ConsensusManager: consensusManager,
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

	if tob.OptimizationNeeded {
		tob.ConsensusManager.UpdatePredictions(tob.PredictedMetrics.TransactionVolume, tob.PredictedMetrics.NodeCount)
	}
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

// GetCurrentBlockTime returns the current block time from the ConsensusManager
func (tob *TOBManager) GetCurrentBlockTime() time.Duration {
	return tob.ConsensusManager.GetCurrentBlockTime()
}
