package detector

import (
	"analizier/backend/src/packet"
	"math"
)

type OverloadDetector struct {
	WindowSize        int
	Sensitivity       float64
	MinBPS            float64
	MinPPS            float64
	UseAdaptive       bool
	FixedBPSThreshold float64
	FixedPPSThreshold float64

	OverloadAbsoluteThreshold float64
	OverloadGrowthFactor      float64

	prevClientHelloCount float64
}

func NewAdaptiveOverloadDetector(windowSize int, sensitivity float64) *OverloadDetector {
	if windowSize <= 0 {
		windowSize = 10
	}
	if sensitivity <= 0 {
		sensitivity = 3.0
	}
	return &OverloadDetector{
		WindowSize:                windowSize,
		Sensitivity:               sensitivity,
		MinBPS:                    1_000_000,
		MinPPS:                    1000,
		UseAdaptive:               true,
		OverloadAbsoluteThreshold: 1000,
		OverloadGrowthFactor:      5.0,
	}
}

func NewFixedOverloadDetector(bps, pps float64) *OverloadDetector {
	return &OverloadDetector{
		FixedBPSThreshold:         bps,
		FixedPPSThreshold:         pps,
		OverloadAbsoluteThreshold: 1000,
		OverloadGrowthFactor:      5.0,
	}
}

func (d *OverloadDetector) Name() string {
	return "OverloadDetector"
}

func (d *OverloadDetector) Analyze(stats packet.FlowStats) DetectionResult {
	return DetectionResult{IsAnomaly: false}
}

func (d *OverloadDetector) AnalyzeWindows(windows []packet.TimeWindow) []packet.TimeWindow {
	if len(windows) == 0 {
		return nil
	}

	d.enrichWindowsWithTLS(windows)

	var overloaded []packet.TimeWindow
	if d.UseAdaptive {
		overloaded = d.analyzeAdaptive(windows)
	} else {
		overloaded = d.analyzeFixed(windows)
	}

	tlsOverloaded := d.analyzeTLSClientHello(windows)
	return unionWindows(overloaded, tlsOverloaded)
}

func (d *OverloadDetector) enrichWindowsWithTLS(windows []packet.TimeWindow) {
	for i := range windows {
		windows[i].ClientHelloCount = float64(windows[i].Stats.TLSFlowCount)
		if i > 0 {
			windows[i].ClientHelloCountPrev = windows[i-1].ClientHelloCount
		} else {
			windows[i].ClientHelloCountPrev = d.prevClientHelloCount
		}
	}
	if len(windows) > 0 {
		d.prevClientHelloCount = windows[len(windows)-1].ClientHelloCount
	}
}

func (d *OverloadDetector) analyzeTLSClientHello(windows []packet.TimeWindow) []packet.TimeWindow {
	overloaded := make([]packet.TimeWindow, 0)
	for _, w := range windows {
		if w.ClientHelloCount > d.OverloadAbsoluteThreshold {
			overloaded = append(overloaded, w)
			continue
		}
		prev := w.ClientHelloCountPrev
		if prev < 1 {
			prev = 1
		}
		if w.ClientHelloCount/prev > d.OverloadGrowthFactor {
			overloaded = append(overloaded, w)
		}
	}
	return overloaded
}

func (d *OverloadDetector) analyzeFixed(windows []packet.TimeWindow) []packet.TimeWindow {
	overloaded := make([]packet.TimeWindow, 0)
	for _, w := range windows {
		if w.Stats.BPS > d.FixedBPSThreshold || w.Stats.PPS > d.FixedPPSThreshold {
			overloaded = append(overloaded, w)
		}
	}
	return overloaded
}

func (d *OverloadDetector) analyzeAdaptive(windows []packet.TimeWindow) []packet.TimeWindow {
	if len(windows) < d.WindowSize {
		return nil
	}

	overloaded := make([]packet.TimeWindow, 0)
	
	// Сначала собираем историю для первого анализируемого окна
	bpsHistory := make([]float64, 0, d.WindowSize)
	ppsHistory := make([]float64, 0, d.WindowSize)
	
	// Инициализируем историю первыми WindowSize окнами
	for i := 0; i < d.WindowSize; i++ {
		bpsHistory = append(bpsHistory, windows[i].Stats.BPS)
		ppsHistory = append(ppsHistory, windows[i].Stats.PPS)
	}

	// Анализируем окна, начиная с WindowSize-го
	for i := d.WindowSize; i < len(windows); i++ {
		avgBPS, stdBPS := meanStdDev(bpsHistory)
		avgPPS, stdPPS := meanStdDev(ppsHistory)

		thBPS := math.Max(avgBPS+d.Sensitivity*stdBPS, d.MinBPS)
		thPPS := math.Max(avgPPS+d.Sensitivity*stdPPS, d.MinPPS)

		if windows[i].Stats.BPS > thBPS || windows[i].Stats.PPS > thPPS {
			overloaded = append(overloaded, windows[i])
		}

		// Сдвигаем окно: удаляем первый элемент, добавляем текущий
		bpsHistory = append(bpsHistory[1:], windows[i].Stats.BPS)
		ppsHistory = append(ppsHistory[1:], windows[i].Stats.PPS)
	}

	return overloaded
}

func unionWindows(a, b []packet.TimeWindow) []packet.TimeWindow {
	seen := make(map[int64]struct{})
	result := make([]packet.TimeWindow, 0, len(a)+len(b))
	for _, w := range a {
		key := w.StartTime.UnixNano()
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, w)
		}
	}
	for _, w := range b {
		key := w.StartTime.UnixNano()
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, w)
		}
	}
	return result
}

func meanStdDev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	var sumSq float64
	for _, v := range values {
		diff := v - mean
		sumSq += diff * diff
	}
	return mean, math.Sqrt(sumSq / float64(len(values)))
}

func (d *OverloadDetector) SetTLSThresholds(absolute, growth float64) {
	d.OverloadAbsoluteThreshold = absolute
	d.OverloadGrowthFactor = growth
}

func (d *OverloadDetector) ResetTLSState() {
	d.prevClientHelloCount = 0
}