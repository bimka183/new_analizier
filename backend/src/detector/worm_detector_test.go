// detector/worm_detector_test.go
package detector

import (
	"analizier/backend/src/packet"
	"fmt"
	"net"
	"testing"
	"time"
)

// Проверка базового обнаружения червя
func TestAnalyze_InitialWormDetection(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("10.0.0.0/8")
	detector := NewWormDetector(100, 1000.0, internalNet)

	stats := packet.FlowStats{
		SrcIP:      "10.0.0.5",
		DstIP:      "8.8.8.8",
		DstPort:    "445",
		CntPackets: 200,
		BPS:        5000.0,
	}

	result := detector.Analyze(stats)
	if !result.IsAnomaly {
		t.Error("Should detect worm activity")
	}
	if result.Type != AnomalyWorm {
		t.Errorf("Expected AnomalyWorm type, got %s", result.Type)
	}
}

// Проверка небезопасных портов
func TestAnalyze_NonSuspiciousPort(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("192.168.0.0/16")
	detector := NewWormDetector(100, 1000.0, internalNet)

	stats := packet.FlowStats{
		SrcIP:      "192.168.1.10",
		DstIP:      "10.0.0.1",
		DstPort:    "80",
		CntPackets: 200,
		BPS:        5000.0,
	}

	result := detector.Analyze(stats)
	if result.IsAnomaly {
		t.Error("Should not detect anomaly for non-suspicious port without TLS")
	}
}

// Проверка низкой интенсивности трафика
func TestAnalyze_LowPacketsAndBPS(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("10.0.0.0/8")
	detector := NewWormDetector(100, 1000.0, internalNet)

	stats := packet.FlowStats{
		SrcIP:      "10.0.0.5",
		DstIP:      "8.8.8.8",
		DstPort:    "445",
		CntPackets: 50,
		BPS:        500.0,
	}

	result := detector.Analyze(stats)
	if result.IsAnomaly {
		t.Error("Should not detect anomaly with low traffic")
	}
}

// Проверка фильтрации внутренних IP
func TestAnalyze_InternalDstIP(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("192.168.0.0/16")
	detector := NewWormDetector(100, 1000.0, internalNet)

	stats := packet.FlowStats{
		SrcIP:      "10.0.0.5",
		DstIP:      "192.168.1.10",
		DstPort:    "445",
		CntPackets: 200,
		BPS:        5000.0,
	}

	result := detector.Analyze(stats)
	if result.IsAnomaly {
		t.Error("Should not detect anomaly for internal destination IP")
	}
}

// Проверка корреляции сканирований - один источник атакует разные цели
func TestAnalyze_CorrelatedWormActivity(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("10.0.0.0/8")
	detector := NewWormDetector(100, 1000.0, internalNet)

	srcIP := "10.0.0.5"

	// Первая атака: заражаем первую цель
	stats1 := packet.FlowStats{
		SrcIP:      srcIP,
		DstIP:      "8.8.8.8",
		DstPort:    "445",
		CntPackets: 200,
		BPS:        5000.0,
	}
	detector.Analyze(stats1)

	// Вторая атака с того же источника на другую цель
	stats2 := packet.FlowStats{
		SrcIP:      srcIP,
		DstIP:      "8.8.4.4",
		DstPort:    "139",
		CntPackets: 150,
		BPS:        3000.0,
	}

	result := detector.Analyze(stats2)
	if !result.IsAnomaly {
		t.Error("Should detect correlated worm activity")
	}
	// При второй атаке scanCount=1, confidence = 0.85 + (1-1)*0.03 = 0.85
	if result.Confidence != 0.85 {
		t.Errorf("Expected confidence 0.85, got %f", result.Confidence)
	}
}

// Проверка обнаружения через TLS на нестандартном порту
func TestAnalyze_TLSWormDetection(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("10.0.0.0/8")
	detector := NewWormDetector(100, 1000.0, internalNet)
	detector.WormMinFlows = 3
	detector.WormMinUniqueDst = 2
	detector.WormDominantJA3Ratio = 0.5
	detector.WormInternalDstRatio = 0.5

	srcIP := "10.0.0.5"
	ja3Hash := "worm_ja3_hash"

	// Отправляем TLS-потоки на НЕподозрительный порт, но с TLS
	for i := 1; i <= 3; i++ {
		stats := packet.FlowStats{
			SrcIP:      srcIP,
			DstIP:      fmt.Sprintf("10.0.1.%d", i),
			DstPort:    "443", // Не подозрительный порт, полагаемся только на TLS
			CntPackets: 200,
			BPS:        5000.0,
			TLS: &packet.TLSInfo{
				JA3: ja3Hash,
			},
		}
		result := detector.Analyze(stats)
		if i == 3 {
			if !result.IsAnomaly {
				t.Errorf("Should detect TLS-based worm activity at flow %d", i)
			}
			if result.Confidence != 0.85 {
				t.Errorf("Expected TLS confidence 0.85, got %f", result.Confidence)
			}
		}
	}
}

// Проверка повышения уверенности при RST
func TestAnalyze_RSTConfidence(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("10.0.0.0/8")
	detector := NewWormDetector(100, 1000.0, internalNet)

	stats := packet.FlowStats{
		SrcIP:      "10.0.0.5",
		DstIP:      "8.8.8.8",
		DstPort:    "445",
		CntPackets: 200,
		BPS:        5000.0,
		CntRST:     150,
	}

	result := detector.Analyze(stats)
	if result.Confidence != 0.75 {
		t.Errorf("Expected confidence 0.75, got %f", result.Confidence)
	}
}

// Проверка очистки устаревших записей
func TestCleanupExpired(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("10.0.0.0/8")
	detector := NewWormDetector(100, 1000.0, internalNet)
	detector.SetCorrelWindow(100 * time.Millisecond)
	detector.SetCleanupInterval(10 * time.Millisecond)

	stats := packet.FlowStats{
		SrcIP:      "10.0.0.5",
		DstIP:      "8.8.8.8",
		DstPort:    "445",
		CntPackets: 200,
		BPS:        5000.0,
	}
	detector.Analyze(stats)

	if detector.GetVictimCount() != 1 {
		t.Error("Should have 1 victim")
	}

	time.Sleep(200 * time.Millisecond)

	// Триггерим очистку
	stats.DstIP = "8.8.4.4"
	result := detector.Analyze(stats)

	if detector.GetVictimCount() != 1 {
		t.Errorf("Expected 1 victim after cleanup, got %d", detector.GetVictimCount())
	}
	
	if !result.IsAnomaly {
		t.Error("New victim should be detected")
	}
}

// Проверка сброса состояния
func TestReset(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("10.0.0.0/8")
	detector := NewWormDetector(100, 1000.0, internalNet)

	stats := packet.FlowStats{
		SrcIP:      "10.0.0.5",
		DstIP:      "8.8.8.8",
		DstPort:    "445",
		CntPackets: 200,
		BPS:        5000.0,
	}
	detector.Analyze(stats)
	detector.Reset()

	if detector.GetVictimCount() != 0 {
		t.Error("Should have no victims after reset")
	}
}

// Проверка расчета уверенности
func TestCalculateConfidence(t *testing.T) {
	_, internalNet, _ := net.ParseCIDR("10.0.0.0/8")
	detector := NewWormDetector(100, 1000.0, internalNet)

	tests := []struct {
		scanCount int
		expected  float64
	}{
		{1, 0.85},
		{5, 0.97},
		{10, 0.99},
	}

	for _, test := range tests {
		confidence := detector.calculateConfidence(test.scanCount)
		if confidence != test.expected {
			t.Errorf("scanCount %d: expected %f, got %f", test.scanCount, test.expected, confidence)
		}
	}
}