package detector

import (
	"analizier/backend/src/packet"
	"fmt"
)

type AnomalyType int

const (
	AnomalyNone AnomalyType = iota
	AnomalyDoS
	AnomalyOverload
	AnomalyScanning
	AnomalyWorm
)

func (a AnomalyType) String() string {
	switch a {
	case AnomalyNone:
		return "None"
	case AnomalyDoS:
		return "DoS/DDoS Attack"
	case AnomalyOverload:
		return "Network Overload"
	case AnomalyScanning:
		return "Network/Port Scanning"
	case AnomalyWorm:
		return "Worm Activity"
	default:
		return fmt.Sprintf("Unknown Anomaly (%d)", a)
	}
}

type DetectionResult struct {
	IsAnomaly  bool
	Confidence float64
	Type       AnomalyType
}

type Detector interface {
	// Возвращает имя детектора. Может пригодиться для отладочной информации
	Name() string
	Analyze(stats packet.FlowStats) DetectionResult
}
