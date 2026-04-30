// detector/worm_detector.go
package detector

import (
	"analizier/backend/src/packet"
	"net"
	"strconv"
	"sync"
	"time"
)

// WormDetector анализирует на основе цепочки "заражение -> сканирование"
type WormDetector struct {
	MinPackets    int
	MinBPS        float64
	SuspiciousDst map[int]string
	InternalNet   *net.IPNet

	mu           sync.RWMutex
	victims      map[string]victimRecord
	correlWindow time.Duration
	cleanupInt   time.Duration
	lastCleanup  time.Time
}

// victimRecord хранит информацию о заражённом хосте
type victimRecord struct {
	infectedAt   time.Time
	infectedPort int
	lastScan     time.Time
	scanCount    int
}

func (d *WormDetector) Name() string {
	return "WormDetector"
}

func NewWormDetector(minPackets int, minBPS float64, internalNet *net.IPNet) *WormDetector {
	// Оставляем только порты, реально связанные с червями (445 – SMB, 139 – NetBIOS, 1433 – MSSQL)
	// 6881 временно убираем, т.к. в чистом дампе много легитимного BitTorrent
	suspicious := map[int]string{
		445:  "SMB",
		139:  "NetBIOS",
		1433: "MSSQL",
	}
	return &WormDetector{
		MinPackets:    minPackets,
		MinBPS:        minBPS,
		SuspiciousDst: suspicious,
		InternalNet:   internalNet,
		victims:       make(map[string]victimRecord),
		correlWindow:  30 * time.Second,
		cleanupInt:    5 * time.Minute,
		lastCleanup:   time.Now(),
	}
}

// Analyze проверяет статистику потока на паттерны червя.
func (d *WormDetector) Analyze(stats packet.FlowStats) DetectionResult {
	// Парсим порт назначения
	dstPortStr := stats.DstPort
	if dstPortStr == "" {
		return DetectionResult{IsAnomaly: false}
	}

	port, err := strconv.Atoi(dstPortStr)
	if err != nil {
		return DetectionResult{IsAnomaly: false}
	}

	// 1. Быстрая проверка: порт не в списке подозрительных
	_, isSuspicious := d.SuspiciousDst[port]
	if !isSuspicious {
		return DetectionResult{IsAnomaly: false}
	}

	// 2. Проверка объёмов трафика (отсекаем одиночные пакеты/шум)
	if stats.CntPackets < d.MinPackets || stats.BPS < d.MinBPS {
		return DetectionResult{IsAnomaly: false}
	}

	// 3. Не анализируем трафик внутри доверенной сети
	if d.InternalNet != nil {
		dstIP := net.ParseIP(stats.DstIP)
		if dstIP != nil && d.InternalNet.Contains(dstIP) {
			return DetectionResult{IsAnomaly: false}
		}
	}

	srcIP := stats.SrcIP
	dstIP := stats.DstIP
	if srcIP == "" || dstIP == "" {
		return DetectionResult{IsAnomaly: false}
	}

	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	// Периодическая очистка устаревших записей
	if now.Sub(d.lastCleanup) > d.cleanupInt {
		d.cleanupExpired(now)
		d.lastCleanup = now
	}

	// Проверяем: не является ли srcIP уже заражённым хостом, сканирующим других
	if record, wasInfected := d.victims[srcIP]; wasInfected {
		if now.Sub(record.infectedAt) <= d.correlWindow {
			// Обновляем запись о заражённом хосте
			record.lastScan = now
			record.scanCount++
			d.victims[srcIP] = record

			// Высокая уверенность: видим цепочку "заразили -> сканирует"
			return DetectionResult{
				IsAnomaly:  true,
				Confidence: d.calculateConfidence(record.scanCount),
				Type:       AnomalyWorm,
			}
		}
	}

	// Помечаем dstIP как потенциально заражённый
	if _, exists := d.victims[dstIP]; !exists {
		d.victims[dstIP] = victimRecord{
			infectedAt:   now,
			infectedPort: port,
			lastScan:     time.Time{},
			scanCount:    0,
		}
	}

	// Стандартное обнаружение подозрительного трафика
	confidence := 0.7

	// Повышаем уверенность если много RST (признак сканирования)
	if stats.CntRST > 0 && stats.CntRST > stats.CntPackets/2 {
		confidence = 0.75
	}

	return DetectionResult{
		IsAnomaly:  true,
		Confidence: confidence,
		Type:       AnomalyWorm,
	}
}

// calculateConfidence вычисляет уверенность на основе количества сканирований
func (d *WormDetector) calculateConfidence(scanCount int) float64 {
	baseConfidence := 0.85
	// Увеличиваем уверенность с каждым новым сканированием (максимум 0.99)
	bonus := float64(scanCount-1) * 0.03
	if bonus > 0.14 {
		bonus = 0.14
	}
	confidence := baseConfidence + bonus
	if confidence > 0.99 {
		confidence = 0.99
	}
	return confidence
}

// cleanupExpired удаляет записи о заражениях старше correlWindow
func (d *WormDetector) cleanupExpired(now time.Time) {
	for ip, record := range d.victims {
		if now.Sub(record.infectedAt) > d.correlWindow {
			delete(d.victims, ip)
		}
	}
}

// GetVictimCount возвращает текущее количество отслеживаемых жертв
func (d *WormDetector) GetVictimCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.victims)
}

// GetActiveVictims возвращает IP активных жертв
func (d *WormDetector) GetActiveVictims() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now()
	var active []string

	for ip, record := range d.victims {
		if now.Sub(record.infectedAt) <= d.correlWindow {
			active = append(active, ip)
		}
	}

	return active
}

// GetStats возвращает статистику детектора для мониторинга
func (d *WormDetector) GetStats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	activeVictims := 0
	scanningVictims := 0
	totalScans := 0
	now := time.Now()

	for _, record := range d.victims {
		if now.Sub(record.infectedAt) <= d.correlWindow {
			activeVictims++
			if record.scanCount > 0 {
				scanningVictims++
				totalScans += record.scanCount
			}
		}
	}

	return map[string]interface{}{
		"total_tracked":     len(d.victims),
		"active_victims":    activeVictims,
		"scanning_victims":  scanningVictims,
		"total_scans":       totalScans,
		"correl_window_sec": d.correlWindow.Seconds(),
	}
}

// SetCorrelWindow позволяет настроить окно корреляции
func (d *WormDetector) SetCorrelWindow(window time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.correlWindow = window
}

// SetCleanupInterval позволяет настроить интервал очистки
func (d *WormDetector) SetCleanupInterval(interval time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanupInt = interval
}

// Reset сбрасывает все данные детектора (для тестов)
func (d *WormDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.victims = make(map[string]victimRecord)
	d.lastCleanup = time.Now()
}