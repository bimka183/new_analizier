package detector

import (
	"analizier/backend/src/packet"
)

type DDoSDetector struct{}

func (d *DDoSDetector) Name() string {
	return "DDoSDetector"
}

// Analyze требуется интерфейсом Detector, но DDoS-детектор работает на окнах.
// Для совместимости возвращаем «не аномалия».
func (d *DDoSDetector) Analyze(stats packet.FlowStats) DetectionResult {
	return DetectionResult{IsAnomaly: false}
}

// AnalyzeWindows – основной метод детектора, анализирует временные окна.
// Возвращает список окон, признанных аномальными.
func (d *DDoSDetector) AnalyzeWindows(windows []packet.TimeWindow) []packet.TimeWindow {
	totalRST := totalRST(windows)
	const (
		bpsThreshold      = 1_000_000
		rstSynRatio       = 15.0
		uniqueDstPortsAbs = 370
		highAvgPorts      = 1000
		windowCount       = 10
	)

	var anomalous []packet.TimeWindow
	if totalRST <= 10 {
		return anomalous
	}

	for i, windowElement := range windows {
		stats := windowElement.Stats

		if stats.BPS <= bpsThreshold {
			continue
		}

		// 1. Аномальное отношение RST/SYN
		if stats.CntSYN > 0 && float64(stats.CntRST)/float64(stats.CntSYN) > rstSynRatio {
			anomalous = append(anomalous, windowElement)
			continue
		}

		// 2. Абсолютное большое количество уникальных портов назначения
		if stats.UniqueDstPorts > uniqueDstPortsAbs {
			anomalous = append(anomalous, windowElement)
			continue
		}

		// 3. Долгосрочное высокое среднее уникальных портов
		if i > windowCount {
			avg := 0.0
			for j := i - windowCount + 1; j <= i; j++ {
				avg += float64(windows[j].Stats.UniqueDstPorts)
			}
			avg /= windowCount
			if avg > highAvgPorts {
				anomalous = append(anomalous, windowElement)
			}
		}
	}
	return anomalous
}

// totalRST – вспомогательная функция для подсчёта RST во всех окнах
func totalRST(windows []packet.TimeWindow) int {
	total := 0
	for _, w := range windows {
		total += w.Stats.CntRST
	}
	return total
}
