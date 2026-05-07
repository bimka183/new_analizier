package detector

import (
	"analizier/backend/src/packet"
	"net"
	"strconv"
	"sync"
	"time"
)

type WormDetector struct {
	MinPackets    int
	MinBPS        float64
	SuspiciousDst map[int]string
	InternalNet   *net.IPNet

	WormMinFlows         int
	WormDominantJA3Ratio float64
	WormMinUniqueDst     int
	WormInternalDstRatio float64

	mu           sync.RWMutex
	victims      map[string]*victimRecord
	srcTLSStats  map[string]*srcTLSStats
	correlWindow time.Duration
	cleanupInt   time.Duration
	lastCleanup  time.Time
}

type victimRecord struct {
	infectedAt   time.Time
	infectedPort int
	lastScan     time.Time
	scanCount    int
}

type srcTLSStats struct {
	totalFlows     int
	ja3Counts      map[string]int
	uniqueDstIPs   map[string]struct{}
	internalDstCnt int
	lastUpdate     time.Time
}

func (d *WormDetector) Name() string {
	return "WormDetector"
}

func NewWormDetector(minPackets int, minBPS float64, internalNet *net.IPNet) *WormDetector {
	return &WormDetector{
		MinPackets: minPackets,
		MinBPS:     minBPS,
		SuspiciousDst: map[int]string{
			445:  "SMB",
			139:  "NetBIOS",
			1433: "MSSQL",
		},
		InternalNet:            internalNet,
		WormMinFlows:           30,
		WormDominantJA3Ratio:   0.80,
		WormMinUniqueDst:       20,
		WormInternalDstRatio:   0.70,
		victims:                make(map[string]*victimRecord),
		srcTLSStats:            make(map[string]*srcTLSStats),
		correlWindow:           30 * time.Second,
		cleanupInt:             5 * time.Minute,
		lastCleanup:            time.Now(),
	}
}

func (d *WormDetector) Analyze(stats packet.FlowStats) DetectionResult {
	dstPortStr := stats.DstPort
	if dstPortStr == "" {
		return DetectionResult{IsAnomaly: false}
	}

	port, err := strconv.Atoi(dstPortStr)
	if err != nil {
		return DetectionResult{IsAnomaly: false}
	}

	_, isSuspiciousPort := d.SuspiciousDst[port]
	if !isSuspiciousPort && stats.TLS == nil {
		return DetectionResult{IsAnomaly: false}
	}

	if stats.CntPackets < d.MinPackets || stats.BPS < d.MinBPS {
		return DetectionResult{IsAnomaly: false}
	}

	srcIP := stats.SrcIP
	dstIP := stats.DstIP
	if srcIP == "" || dstIP == "" {
		return DetectionResult{IsAnomaly: false}
	}

	// Для suspicious портов: игнорируем внутренние dstIP
	if isSuspiciousPort && d.isInternalIP(dstIP) {
		return DetectionResult{IsAnomaly: false}
	}

	now := time.Now()

	d.mu.Lock()
	defer d.mu.Unlock()

	if now.Sub(d.lastCleanup) > d.cleanupInt {
		d.cleanupExpired(now)
		d.lastCleanup = now
	}

	if victim, wasInfected := d.victims[srcIP]; wasInfected {
		if now.Sub(victim.infectedAt) <= d.correlWindow {
			victim.lastScan = now
			victim.scanCount++
			return DetectionResult{
				IsAnomaly:  true,
				Confidence: d.calculateConfidence(victim.scanCount),
				Type:       AnomalyWorm,
			}
		}
		delete(d.victims, srcIP)
	}

	if stats.TLS != nil {
		if d.checkTLSAnomaly(srcIP, stats.TLS, dstIP, now) {
			d.markAsInfected(srcIP, 0, now)
			return DetectionResult{
				IsAnomaly:  true,
				Confidence: 0.85,
				Type:       AnomalyWorm,
			}
		}
		return DetectionResult{IsAnomaly: false}
	}

	if isSuspiciousPort {
		d.markAsInfected(srcIP, port, now)

		confidence := 0.70
		if stats.CntRST > 0 && stats.CntRST > stats.CntPackets/2 {
			confidence = 0.75
		}
		return DetectionResult{
			IsAnomaly:  true,
			Confidence: confidence,
			Type:       AnomalyWorm,
		}
	}

	return DetectionResult{IsAnomaly: false}
}

func (d *WormDetector) checkTLSAnomaly(srcIP string, tlsInfo *packet.TLSInfo, dstIP string, now time.Time) bool {
	stats, exists := d.srcTLSStats[srcIP]
	if !exists {
		stats = &srcTLSStats{
			totalFlows:   0,
			ja3Counts:    make(map[string]int),
			uniqueDstIPs: make(map[string]struct{}),
			lastUpdate:   now,
		}
		d.srcTLSStats[srcIP] = stats
	}

	stats.totalFlows++
	stats.ja3Counts[tlsInfo.JA3]++
	stats.uniqueDstIPs[dstIP] = struct{}{}
	stats.lastUpdate = now

	// Для TLS учитываем внутренние адреса в статистике
	if d.isInternalIP(dstIP) {
		stats.internalDstCnt++
	}

	if stats.totalFlows < d.WormMinFlows {
		return false
	}

	dominantCount := d.getDominantJACount(stats.ja3Counts)
	dominantRatio := float64(dominantCount) / float64(stats.totalFlows)
	uniqueDstCount := len(stats.uniqueDstIPs)
	internalRatio := float64(stats.internalDstCnt) / float64(stats.totalFlows)

	return dominantRatio >= d.WormDominantJA3Ratio &&
		uniqueDstCount >= d.WormMinUniqueDst &&
		internalRatio >= d.WormInternalDstRatio
}

func (d *WormDetector) getDominantJACount(ja3Counts map[string]int) int {
	maxCount := 0
	for _, count := range ja3Counts {
		if count > maxCount {
			maxCount = count
		}
	}
	return maxCount
}

func (d *WormDetector) isInternalIP(ipStr string) bool {
	if d.InternalNet == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return d.InternalNet.Contains(ip)
}

func (d *WormDetector) markAsInfected(srcIP string, port int, now time.Time) {
	if _, exists := d.victims[srcIP]; !exists {
		d.victims[srcIP] = &victimRecord{
			infectedAt:   now,
			infectedPort: port,
			lastScan:     time.Time{},
			scanCount:    0,
		}
	}
}

func (d *WormDetector) calculateConfidence(scanCount int) float64 {
	if scanCount <= 1 {
		return 0.85
	}

	bonus := float64(scanCount-1) * 0.03
	if bonus > 0.14 {
		bonus = 0.14
	}

	confidence := 0.85 + bonus
	if confidence > 0.99 {
		confidence = 0.99
	}
	return confidence
}

func (d *WormDetector) cleanupExpired(now time.Time) {
	for ip, record := range d.victims {
		if now.Sub(record.infectedAt) > d.correlWindow {
			delete(d.victims, ip)
		}
	}
	for ip, stats := range d.srcTLSStats {
		if now.Sub(stats.lastUpdate) > d.correlWindow*2 {
			delete(d.srcTLSStats, ip)
		}
	}
}

func (d *WormDetector) GetVictimCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.victims)
}

func (d *WormDetector) GetActiveVictims() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now()
	active := make([]string, 0, len(d.victims))

	for ip, record := range d.victims {
		if now.Sub(record.infectedAt) <= d.correlWindow {
			active = append(active, ip)
		}
	}
	return active
}

func (d *WormDetector) GetStats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now()
	totalTracked := len(d.victims)
	var activeVictims, scanningVictims, totalScans int

	for _, record := range d.victims {
		if now.Sub(record.infectedAt) <= d.correlWindow {
			activeVictims++
			if record.scanCount > 0 {
				scanningVictims++
				totalScans += record.scanCount
			}
		}
	}

	suspiciousTLS := 0
	for _, stats := range d.srcTLSStats {
		if stats.totalFlows >= d.WormMinFlows {
			suspiciousTLS++
		}
	}

	return map[string]interface{}{
		"total_tracked":      totalTracked,
		"active_victims":     activeVictims,
		"scanning_victims":   scanningVictims,
		"total_scans":        totalScans,
		"suspicious_tls_src": suspiciousTLS,
		"correl_window_sec":  d.correlWindow.Seconds(),
	}
}

func (d *WormDetector) SetCorrelWindow(window time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.correlWindow = window
}

func (d *WormDetector) SetCleanupInterval(interval time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanupInt = interval
}

func (d *WormDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.victims = make(map[string]*victimRecord)
	d.srcTLSStats = make(map[string]*srcTLSStats)
	d.lastCleanup = time.Now()
}