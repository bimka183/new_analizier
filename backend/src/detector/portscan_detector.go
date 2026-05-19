package detector

import (
	"analizier/backend/src/packet"
	"math"
	"sort"
	"time"
)

const (
	portScanMinStatSample = 5
	portScanMADCoeff      = 0.6745
)

// PortScanDetector выявляет сканирование портов на уровне источника (SrcIP).
type PortScanDetector struct {
	MinUniqueDstPorts       int
	FailedRatioThreshold    float64
	MADZScoreThreshold      float64
	MinSourcesForAdaptation int
	IQRMultiplier           float64
	IncludeMediumAlerts     bool

	// per-flow fallback (Analyze)
	MinPacketsThreshold int
	MaxDuration         time.Duration
	RSTRatioThreshold   float64
}

func NewPortScanDetector() *PortScanDetector {
	return &PortScanDetector{
		MinUniqueDstPorts:       30,
		FailedRatioThreshold:    0.7,
		MADZScoreThreshold:      3.5,
		MinSourcesForAdaptation: 10,
		IQRMultiplier:           1.5,
		IncludeMediumAlerts:     false,
		MinPacketsThreshold:     3,
		MaxDuration:             100 * time.Millisecond,
		RSTRatioThreshold:       0.3,
	}
}

func (d *PortScanDetector) Name() string {
	return "PortScanDetector"
}

// Analyze — per-flow fallback; основная разметка через ScanningSources.
func (d *PortScanDetector) Analyze(stats packet.FlowStats) DetectionResult {
	if stats.CntPackets == 0 {
		return DetectionResult{IsAnomaly: false, Confidence: 0, Type: AnomalyNone}
	}

	score := 0.0
	if stats.CntSYN > 0 && stats.CntACK == 0 {
		score += 0.50
	}
	if stats.CntPackets <= d.MinPacketsThreshold {
		score += 0.25
	}
	rstRatio := float64(stats.CntRST) / float64(stats.CntPackets)
	if rstRatio >= d.RSTRatioThreshold {
		score += 0.15
	}
	if stats.Duration <= d.MaxDuration && stats.CntSYN > 0 {
		score += 0.10
	}
	if score > 1.0 {
		score = 1.0
	}

	return DetectionResult{
		IsAnomaly:  score >= 0.5,
		Confidence: score,
		Type:       AnomalyScanning,
	}
}

// ScanningSources возвращает SrcIP, для которых обнаружено сканирование портов.
func (d *PortScanDetector) ScanningSources(
	flows map[string]*packet.FlowInfo,
	captureDuration time.Duration,
) map[string]bool {
	out := make(map[string]bool)
	if len(flows) == 0 {
		return out
	}

	for _, flow := range flows {
		packet.AnalyzeFlow(flow)
	}

	sources := packet.AggregateBySource(flows, captureDuration)
	if len(sources) == 0 {
		return out
	}

	portsAll := make([]float64, len(sources))
	for i := range sources {
		portsAll[i] = float64(sources[i].UniqueDstPorts)
	}
	p95Ports := 0.0
	if len(sources) >= d.MinSourcesForAdaptation {
		p95Ports = portScanPercentile(portsAll, 95)
	}

	for i := range sources {
		ss := sources[i]
		fr := failedRatioForSource(flows, ss.SourceIP)
		hard, adaptive, madOutlier := d.portSignals(ss, sources, i, p95Ports)
		portHit := hard || adaptive || madOutlier

		iqrHit := false
		if len(sources) >= portScanMinStatSample {
			iqrHit = portScanIQRHighOutlier(float64(ss.UniqueDstPorts), portsAll, d.IQRMultiplier)
		}

		strong := portHit && fr >= d.FailedRatioThreshold
		if strong {
			out[ss.SourceIP] = true
			continue
		}

		if !d.IncludeMediumAlerts {
			continue
		}
		signals := 0
		if portHit {
			signals++
		}
		if madOutlier || iqrHit {
			signals++
		}
		if fr >= d.FailedRatioThreshold {
			signals++
		}
		if signals >= 2 {
			out[ss.SourceIP] = true
		}
	}

	return out
}

func (d *PortScanDetector) portSignals(
	ss packet.SourceStats,
	all []packet.SourceStats,
	idx int,
	p95Ports float64,
) (hard, adaptive, madOutlier bool) {
	hard = ss.UniqueDstPorts > d.MinUniqueDstPorts

	if len(all) >= d.MinSourcesForAdaptation {
		th := float64(d.MinUniqueDstPorts)
		if p95Ports > th {
			th = p95Ports
		}
		adaptive = float64(ss.UniqueDstPorts) > th
	}

	if len(all) >= d.MinSourcesForAdaptation {
		others := make([]float64, 0, len(all)-1)
		for j := range all {
			if j == idx {
				continue
			}
			others = append(others, float64(all[j].UniqueDstPorts))
		}
		if len(others) >= portScanMinStatSample {
			if zm, ok := portScanMADHighScore(float64(ss.UniqueDstPorts), others, portScanMADCoeff); ok && zm > d.MADZScoreThreshold {
				madOutlier = true
			}
		}
	}

	return hard, adaptive, madOutlier
}

func portScanSourceIP(f *packet.FlowInfo) string {
	if f == nil {
		return ""
	}
	if f.Stats.SrcIP != "" {
		return f.Stats.SrcIP
	}
	if f.SourceIP != "" {
		return f.SourceIP
	}
	if len(f.Packets) > 0 {
		return f.Packets[0].SrcIP
	}
	return ""
}

func flowLooksFailed(stats packet.FlowStats) bool {
	if stats.CntPackets == 0 {
		return false
	}
	if stats.CntSYN > 0 && stats.CntACK == 0 {
		return true
	}
	return float64(stats.CntRST)/float64(stats.CntPackets) >= 0.3
}

func failedRatioForSource(flows map[string]*packet.FlowInfo, srcIP string) float64 {
	if srcIP == "" {
		return 0
	}
	total := 0
	failed := 0
	for _, f := range flows {
		if portScanSourceIP(f) != srcIP {
			continue
		}
		total++
		if flowLooksFailed(f.Stats) {
			failed++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(failed) / float64(total)
}

func portScanPercentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	xs := append([]float64(nil), values...)
	sort.Float64s(xs)
	return portScanPercentileLinear(xs, p)
}

func portScanPercentileLinear(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := (float64(len(sorted) - 1)) * p / 100.0
	lo := int(math.Floor(pos))
	hi := int(math.Ceil(pos))
	if lo == hi {
		return sorted[lo]
	}
	w := pos - float64(lo)
	return sorted[lo]*(1-w) + sorted[hi]*w
}

func portScanIQRHighOutlier(current float64, history []float64, k float64) bool {
	if len(history) < portScanMinStatSample {
		return false
	}
	xs := append([]float64(nil), history...)
	sort.Float64s(xs)
	q1 := portScanPercentileLinear(xs, 25)
	q3 := portScanPercentileLinear(xs, 75)
	fence := q3 + k*(q3-q1)
	return current > fence
}

func portScanMedian(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	n := len(cp)
	if n%2 == 1 {
		return cp[n/2]
	}
	return (cp[n/2-1] + cp[n/2]) / 2
}

func portScanMADHighScore(x float64, history []float64, madK float64) (float64, bool) {
	if len(history) < portScanMinStatSample {
		return 0, false
	}
	med := portScanMedian(history)
	devs := make([]float64, len(history))
	for i, v := range history {
		devs[i] = math.Abs(v - med)
	}
	mad := portScanMedian(devs)
	if mad < 1e-12 {
		return 0, false
	}
	return madK * (x - med) / mad, true
}
