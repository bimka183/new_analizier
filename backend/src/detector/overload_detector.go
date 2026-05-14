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
	
	// Z-score, EWMA и адаптивный порог
	ppsHistory              []float64
	zScoreHistory           []float64
	adaptiveThresholdActive bool
	consecutiveCleanWindows int
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
		ppsHistory:                make([]float64, 0, 30),
		zScoreHistory:             make([]float64, 0, 3),
		adaptiveThresholdActive:   false,
		consecutiveCleanWindows:   0,
	}
}

func NewFixedOverloadDetector(bps, pps float64) *OverloadDetector {
	return &OverloadDetector{
		FixedBPSThreshold:         bps,
		FixedPPSThreshold:         pps,
		OverloadAbsoluteThreshold: 1000,
		OverloadGrowthFactor:      5.0,
		ppsHistory:                make([]float64, 0, 30),
		zScoreHistory:             make([]float64, 0, 3),
		adaptiveThresholdActive:   false,
		consecutiveCleanWindows:   0,
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
	currentThreshold := d.getCurrentThreshold()
	
	overloaded := make([]packet.TimeWindow, 0)
	for _, w := range windows {
		if w.ClientHelloCount > currentThreshold {
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
	
	bpsHistory := make([]float64, 0, d.WindowSize)
	ppsHistory := make([]float64, 0, d.WindowSize)
	
	// Инициализация истории
	for i := 0; i < d.WindowSize; i++ {
		bpsHistory = append(bpsHistory, windows[i].Stats.BPS)
		ppsHistory = append(ppsHistory, windows[i].Stats.PPS)
		d.ppsHistory = append(d.ppsHistory, windows[i].Stats.PPS)
	}

	// Анализ окон
	for i := d.WindowSize; i < len(windows); i++ {
		currentWindow := windows[i]
		currentPPS := currentWindow.Stats.PPS
		
		// Z-score анализ
		var zScore float64
		zScoreValid := false
		if len(d.ppsHistory) >= 10 {
			zScore, zScoreValid = packet.ZScore(currentPPS, d.ppsHistory)
			
			if zScoreValid && zScore > 3.0 {
				_ = zScore
			}
			
			if zScoreValid {
				d.zScoreHistory = append(d.zScoreHistory, zScore)
				if len(d.zScoreHistory) > 3 {
					d.zScoreHistory = d.zScoreHistory[1:]
				}
			}
		}
		
		// EWMA-тренд
		isEWMAGrowth := false
		if len(d.ppsHistory) >= 5 {
			last5Values := make([]float64, 0, 6)
			startIdx := len(d.ppsHistory) - 5
			if startIdx < 0 {
				startIdx = 0
			}
			last5Values = append(last5Values, d.ppsHistory[startIdx:]...)
			last5Values = append(last5Values, currentPPS)
			
			if len(last5Values) >= 2 {
				ewmaValues := make([]float64, len(last5Values))
				for j := 0; j < len(last5Values); j++ {
					ewma, _ := packet.EWMA(last5Values[:j+1], 0.3)
					ewmaValues[j] = ewma
				}
				
				isEWMAGrowth = true
				for j := 1; j < len(ewmaValues); j++ {
					if ewmaValues[j] <= ewmaValues[j-1] {
						isEWMAGrowth = false
						break
					}
				}
			}
		}
		
		// Мягкое снижение порога
		hasRecentZAbove2 := false
		for _, z := range d.zScoreHistory {
			if z > 2.0 {
				hasRecentZAbove2 = true
				break
			}
		}
		
		if hasRecentZAbove2 && !d.adaptiveThresholdActive {
			d.adaptiveThresholdActive = true
			d.consecutiveCleanWindows = 0
		}
		
		if d.adaptiveThresholdActive {
			d.consecutiveCleanWindows++
			if d.consecutiveCleanWindows >= 5 {
				d.adaptiveThresholdActive = false
				d.consecutiveCleanWindows = 0
			}
		}
		
		// Основные правила детектирования
		avgBPS, stdBPS := meanStdDev(bpsHistory)
		avgPPS, stdPPS := meanStdDev(ppsHistory)

		thBPS := math.Max(avgBPS+d.Sensitivity*stdBPS, d.MinBPS)
		thPPS := math.Max(avgPPS+d.Sensitivity*stdPPS, d.MinPPS)

		if d.adaptiveThresholdActive {
			thPPS = math.Max(thPPS*0.7, d.MinPPS)
			thBPS = math.Max(thBPS*0.7, d.MinBPS)
		}

		isOverloaded := currentWindow.Stats.BPS > thBPS || currentWindow.Stats.PPS > thPPS
		
		if isEWMAGrowth && !isOverloaded {
			// постепенный рост нагрузки
		}
		
		if isOverloaded {
			overloaded = append(overloaded, currentWindow)
		}

		// Сдвиг окон
		bpsHistory = append(bpsHistory[1:], currentWindow.Stats.BPS)
		ppsHistory = append(ppsHistory[1:], currentPPS)
		
		d.ppsHistory = append(d.ppsHistory, currentPPS)
		if len(d.ppsHistory) > 30 {
			d.ppsHistory = d.ppsHistory[1:]
		}
	}

	return overloaded
}

// getCurrentThreshold возвращает текущий порог для TLS
func (d *OverloadDetector) getCurrentThreshold() float64 {
	if d.adaptiveThresholdActive {
		return d.OverloadAbsoluteThreshold * 0.7
	}
	return d.OverloadAbsoluteThreshold
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
	d.ppsHistory = make([]float64, 0, 30)
	d.zScoreHistory = make([]float64, 0, 3)
	d.adaptiveThresholdActive = false
	d.consecutiveCleanWindows = 0
}