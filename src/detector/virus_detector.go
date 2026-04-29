package detector

import (
	"analizier/src/packet"
	"strconv"
)

type VirusDetector struct {
	BlacklistedIPs  map[string]bool
	WhitelistedIPs  map[string]bool
	SuspiciousPorts map[int]PortRule
	MinPackets      int
	MinBPS          float64 // глобальный минимальный BPS (если не указан в правиле)
}

type PortRule struct {
	MaxDurationSec    float64
	MinDurationSec    float64
	MaxRSTPerSYNRatio float64
	MinAvgPacketSize  float64
	MaxAvgPacketSize  float64
	MinBPSThreshold   float64 // новое поле: минимальный BPS для срабатывания
	AlwaysAnomaly     bool
	MinPackets        int
}

func NewVirusDetector(whitelistIPs []string) *VirusDetector {
	blacklist := map[string]bool{
		"185.130.5.253":   true,
		"94.102.61.78":    true,
		"5.188.86.122":    true,
		"195.54.160.149":  true,
		"176.113.115.146": true,
		"91.219.236.195":  true,
		"79.137.203.161":  true,
	}

	whitelist := make(map[string]bool)
	for _, ip := range whitelistIPs {
		whitelist[ip] = true
	}

	rules := map[int]PortRule{
		445: {
			MaxDurationSec:    0.5,
			MaxRSTPerSYNRatio: 0.3,
			MinAvgPacketSize:  100,
			MinPackets:        5,
			MinBPSThreshold:   50000,
		},
		139: {
			MaxDurationSec:    0.5,
			MaxRSTPerSYNRatio: 0.3,
			MinAvgPacketSize:  100,
			MinPackets:        5,
			MinBPSThreshold:   15000,
		},
		1433: {
			MaxDurationSec:    0.5,
			MaxRSTPerSYNRatio: 0.2,
			MinAvgPacketSize:  50,
			MinPackets:        4,
			MinBPSThreshold:   15000,
		},
		8080: {
			MinAvgPacketSize: 100,
			MaxDurationSec:   1.0,
			MinPackets:       6,
			MinBPSThreshold:  80000,
		},
		5900: {
			MaxDurationSec:  2.0,
			MinPackets:      5,
			MinBPSThreshold: 10000,
		},
	}

	return &VirusDetector{
		BlacklistedIPs:  blacklist,
		WhitelistedIPs:  whitelist,
		SuspiciousPorts: rules,
		MinPackets:      5,
		MinBPS:          0,
	}
}

func (d *VirusDetector) Name() string {
	return "VirusDetector"
}

func (d *VirusDetector) Analyze(stats packet.FlowStats) DetectionResult {
	if d.WhitelistedIPs[stats.DstIP] {
		return DetectionResult{IsAnomaly: false}
	}
	if d.BlacklistedIPs[stats.DstIP] {
		return DetectionResult{IsAnomaly: true, Confidence: 0.85, Type: AnomalyVirus}
	}
	if stats.CntPackets < d.MinPackets {
		return DetectionResult{IsAnomaly: false}
	}
	if stats.DstPort == "" {
		return DetectionResult{IsAnomaly: false}
	}
	port, err := strconv.Atoi(stats.DstPort)
	if err != nil {
		return DetectionResult{IsAnomaly: false}
	}
	rule, exists := d.SuspiciousPorts[port]
	if !exists {
		return DetectionResult{IsAnomaly: false}
	}
	if d.isAnomalousByRule(stats, rule) {
		confidence := 0.7
		if rule.AlwaysAnomaly {
			confidence = 0.8
		}
		return DetectionResult{IsAnomaly: true, Confidence: confidence, Type: AnomalyVirus}
	}
	return DetectionResult{IsAnomaly: false}
}

func (d *VirusDetector) isAnomalousByRule(stats packet.FlowStats, rule PortRule) bool {
	minPkts := rule.MinPackets
	if minPkts == 0 {
		minPkts = d.MinPackets
	}
	if stats.CntPackets < minPkts {
		return false
	}
	// Проверка минимального BPS (новое)
	if rule.MinBPSThreshold > 0 && stats.BPS < rule.MinBPSThreshold {
		return false
	}
	if rule.AlwaysAnomaly {
		return true
	}
	if rule.MaxDurationSec > 0 && stats.Duration.Seconds() < rule.MaxDurationSec {
		return true
	}
	if rule.MinDurationSec > 0 && stats.Duration.Seconds() > rule.MinDurationSec {

	}
	if rule.MaxRSTPerSYNRatio > 0 && stats.CntSYN > 0 {
		ratio := float64(stats.CntRST) / float64(stats.CntSYN)
		if ratio > rule.MaxRSTPerSYNRatio {
			return true
		}
	}
	if rule.MinAvgPacketSize > 0 && stats.AvgPacketSize < rule.MinAvgPacketSize {
		return true
	}
	if rule.MaxAvgPacketSize > 0 && stats.AvgPacketSize > rule.MaxAvgPacketSize {
		return true
	}
	return false
}
