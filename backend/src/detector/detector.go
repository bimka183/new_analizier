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
	AnomalyP2MP
	AnomalyFlowSwitching
	AnomalyVirus
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
	case AnomalyP2MP:
		return "Point-to-Multipoint"
	case AnomalyFlowSwitching:
		return "Flow Switching"
	case AnomalyVirus:
		return "Confirmed Virus Activity"
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

// FlowDetector — интерфейс для детекторов, работающих на уровне потока (FlowInfo),
// а не на уровне статистики (FlowStats). Например, P2MP и FlowSwitching детекторы.
type FlowDetector interface {
	Name() string
	AnalyzeFlow(flow *packet.FlowInfo) DetectionResult
}
