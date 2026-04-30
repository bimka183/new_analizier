package detector

// D0A4D098D098D0A2D0BED0B2D186D18B20D0BCD0B0D0BAD0B0D0BAD0B8
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
		synThreshold      = 1000
		synAckRatio       = 3.0
		synHistoricRatio  = 3.0
		synPerIPThreshold = 3.0
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
				continue
			}
		}

		// 4. SYN-flood
		if stats.CntSYN > synThreshold {
			ratio := float64(stats.CntSYN)
			if stats.CntACK > 0 {
				ratio /= float64(stats.CntSYN)
			}

			if ratio <= synAckRatio {
				continue
			}

			synPerIP := 0.0
			if stats.UniqueSrcIPs > 0 {
				synPerIP = float64(stats.CntSYN) / float64(stats.UniqueSrcIPs)
			}

			avgSyn := 0.0
			if i >= windowCount {
				for j := i - windowCount; j < i; j++ {
					avgSyn += float64(windows[j].Stats.CntSYN)
				}
				avgSyn /= float64(windowCount)
			}

			if (avgSyn > 0 && float64(stats.CntSYN) > avgSyn*synHistoricRatio) || (avgSyn == 0.0 && stats.CntSYN > synThreshold) {
				if synPerIP > 0 && synPerIP < synPerIPThreshold {
					anomalous = append(anomalous, windowElement)
					continue
				}
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
