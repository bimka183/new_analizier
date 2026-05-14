package detector

// D0A4D098D098D0A2D0BED0B2D186D18B20D0BCD0B0D0BAD0B0D0BAD0B8

import (
	"analizier/backend/src/packet"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// minStatSample — минимальный размер выборки для Mean/StdDev/Z (ТЗ по статистике).
const minStatSample = 5

// ewmaChangeLogAbsEps — игнорировать дробный шум при логировании приращения EWMA по BPS.
const ewmaChangeLogAbsEps = 1e-3

// Пороги по report_sourcestats.pdf §3.3 (amplification) и §4 (MAD среди источников).
const (
	minAmplificationActors = 10
	minAmplificationUDP    = 5 // минимум источников с UDP-потоком на порт-усилитель
)

var amplificationUDPPorts = map[int]struct{}{
	53: {}, 123: {}, 11211: {}, 389: {}, 1900: {},
}

var ewmaBPSLog struct {
	sync.Mutex
	initialized bool
	anchor      float64 // последнее значение EWMA, уже отражённое в stdout
	trackedCur  float64 // последнее обработанное EWMA в текущем AnalyzeWindows
	lastPrint   time.Time
}

func ewmaBPSLogReset() {
	ewmaBPSLog.Lock()
	defer ewmaBPSLog.Unlock()
	ewmaBPSLog.initialized = false
	ewmaBPSLog.anchor = 0
	ewmaBPSLog.trackedCur = 0
	ewmaBPSLog.lastPrint = time.Time{}
}

// ewmaBPSLogRecord фиксирует очередное значение EWMA; в stdout — только приращение к последнему выведенному.
func ewmaBPSLogRecord(cur float64) {
	ewmaBPSLog.Lock()
	defer ewmaBPSLog.Unlock()

	if !ewmaBPSLog.initialized {
		ewmaBPSLog.initialized = true
		ewmaBPSLog.anchor = cur
		ewmaBPSLog.trackedCur = cur
		return
	}

	ewmaBPSLog.trackedCur = cur
	delta := cur - ewmaBPSLog.anchor
	if math.Abs(delta) <= ewmaChangeLogAbsEps {
		return
	}

	now := time.Now()
	if ewmaBPSLog.lastPrint.IsZero() || now.Sub(ewmaBPSLog.lastPrint) >= time.Second {
		fmt.Fprintf(os.Stdout, "DDoS адаптивный признак BPS (EWMA): изменение %+g\n", delta)
		ewmaBPSLog.anchor = cur
		ewmaBPSLog.lastPrint = now
	}
}

// ewmaBPSLogFlush выводит накопленное приращение в конце анализа, если оно не было выведено из‑за лимита 1 с.
func ewmaBPSLogFlush() {
	ewmaBPSLog.Lock()
	defer ewmaBPSLog.Unlock()
	if !ewmaBPSLog.initialized {
		return
	}
	delta := ewmaBPSLog.trackedCur - ewmaBPSLog.anchor
	if math.Abs(delta) <= ewmaChangeLogAbsEps {
		return
	}
	fmt.Fprintf(os.Stdout, "DDoS адаптивный признак BPS (EWMA): изменение %+g\n", delta)
	ewmaBPSLog.anchor = ewmaBPSLog.trackedCur
	ewmaBPSLog.lastPrint = time.Now()
}

type DDoSDetector struct{}

func (d *DDoSDetector) Name() string {
	return "DDoSDetector"
}

// Analyze требуется интерфейсом Detector, но DDoS-детектор работает на окнах.
// Для совместимости возвращаем «не аномалия».
func (d *DDoSDetector) Analyze(stats packet.FlowStats) DetectionResult {
	return DetectionResult{IsAnomaly: false}
}

// AnalyzeWindows — обёртка без потоков (тесты, CLI); per-source правила не применяются.
func (d *DDoSDetector) AnalyzeWindows(windows []packet.TimeWindow) []packet.TimeWindow {
	return d.AnalyzeWindowsWithFlows(windows, nil, 0)
}

// AnalyzeWindowsWithFlows анализирует окна и при наличии проанализированных потоков
// дополняет результат признаками по агрегации источника (SourceStats), см. report_sourcestats §3.3.
func (d *DDoSDetector) AnalyzeWindowsWithFlows(windows []packet.TimeWindow, flows map[string]*packet.FlowInfo, captureDuration time.Duration) []packet.TimeWindow {
	base := d.analyzeWindowsFromStats(windows)
	if flows == nil || captureDuration <= 0 || len(windows) == 0 {
		return base
	}
	extra := d.sourceAugmentedWindows(windows, flows, captureDuration)
	return unionTimeWindows(base, extra)
}

// analyzeWindowsFromStats — прежняя логика только по WindowStats (скользящая история окон).
func (d *DDoSDetector) analyzeWindowsFromStats(windows []packet.TimeWindow) []packet.TimeWindow {
	totalRST := totalRST(windows)
	const (
		bpsThreshold      = 1_000_000
		rstSynRatioLegacy = 15.0
		uniqueDstPortsAbs = 370
		highAvgPorts      = 1000
		windowCount       = 10
		synThreshold      = 1000
		synAckRatio       = 3.0
		synHistoricRatio  = 3.0
		synPerIPThreshold = 3.0

		zReliableBPS = 10
		zStrong      = 3.0
		tukeyK       = 1.5
		madCoeff     = 0.6745
		madZStrong   = 3.5
		ewmaAlpha    = 0.3
	)

	var anomalous []packet.TimeWindow
	if totalRST <= 10 {
		return anomalous
	}

	ewmaBPSLogReset()

	bpsEwma := make([]float64, len(windows))
	var ewmaPrev float64
	for i := range windows {
		b := windows[i].Stats.BPS
		if i == 0 {
			ewmaPrev = b
		} else {
			ewmaPrev = ewmaAlpha*b + (1-ewmaAlpha)*ewmaPrev
		}
		bpsEwma[i] = ewmaPrev
	}

	for i, windowElement := range windows {
		ewmaBPSLogRecord(bpsEwma[i])

		stats := windowElement.Stats

		trailStart := i - windowCount
		if trailStart < 0 {
			trailStart = 0
		}
		trailBPS := make([]float64, 0, i-trailStart)
		for j := trailStart; j < i; j++ {
			trailBPS = append(trailBPS, bpsEwma[j])
		}

		bpsLegacy := stats.BPS > bpsThreshold
		bpsAdaptive := false
		if len(trailBPS) >= zReliableBPS {
			if z, ok := zScore(bpsEwma[i], trailBPS); ok && z > zStrong {
				bpsAdaptive = true
			}
		}
		if !bpsLegacy && !bpsAdaptive {
			continue
		}

		// 1. RST/SYN
		rstSynLegacy := stats.CntSYN > 0 && float64(stats.CntRST)/float64(stats.CntSYN) > rstSynRatioLegacy
		rstSynHist := make([]float64, 0, i-trailStart)
		for j := trailStart; j < i; j++ {
			sj := windows[j].Stats
			if sj.CntSYN > 0 {
				rstSynHist = append(rstSynHist, float64(sj.CntRST)/float64(sj.CntSYN))
			}
		}
		rstSynAdaptive := false
		if stats.CntSYN > 0 && len(rstSynHist) >= minStatSample {
			cur := float64(stats.CntRST) / float64(stats.CntSYN)
			if z, ok := zScore(cur, rstSynHist); ok && z > zStrong {
				rstSynAdaptive = true
			}
			if tukeyHighOutlier(cur, rstSynHist, tukeyK) {
				rstSynAdaptive = true
			}
		}
		if rstSynLegacy || rstSynAdaptive {
			anomalous = append(anomalous, windowElement)
			continue
		}

		// 2. Уникальные dst-порты
		portsHist := make([]float64, 0, i-trailStart)
		for j := trailStart; j < i; j++ {
			portsHist = append(portsHist, float64(windows[j].Stats.UniqueDstPorts))
		}
		portsLegacy := float64(stats.UniqueDstPorts) > float64(uniqueDstPortsAbs)
		portsAdaptive := false
		if len(portsHist) >= minStatSample {
			cur := float64(stats.UniqueDstPorts)
			if z, ok := zScore(cur, portsHist); ok && z > zStrong {
				portsAdaptive = true
			}
			if tukeyHighOutlier(cur, portsHist, tukeyK) {
				portsAdaptive = true
			}
			if zm, ok := madHighScore(cur, portsHist, madCoeff); ok && zm > madZStrong {
				portsAdaptive = true
			}
		}
		if portsLegacy || portsAdaptive {
			anomalous = append(anomalous, windowElement)
			continue
		}

		// 3. Скользящее среднее уникальных dst-портов
		if i > windowCount {
			var curAvg float64
			for j := i - windowCount + 1; j <= i; j++ {
				curAvg += float64(windows[j].Stats.UniqueDstPorts)
			}
			curAvg /= float64(windowCount)

			avgHist := make([]float64, 0, i-windowCount-1)
			for k := windowCount + 1; k < i; k++ {
				var a float64
				for j := k - windowCount + 1; j <= k; j++ {
					a += float64(windows[j].Stats.UniqueDstPorts)
				}
				a /= float64(windowCount)
				avgHist = append(avgHist, a)
			}

			avgLegacy := curAvg > float64(highAvgPorts)
			avgAdaptive := false
			if len(avgHist) >= minStatSample {
				if z, ok := zScore(curAvg, avgHist); ok && z > zStrong {
					avgAdaptive = true
				}
				if tukeyHighOutlier(curAvg, avgHist, tukeyK) {
					avgAdaptive = true
				}
			}
			if avgLegacy || avgAdaptive {
				anomalous = append(anomalous, windowElement)
				continue
			}
		}

		// 4. SYN-flood (SYN/ACK исправлено: ранее делили на CntSYN)
		synHist := make([]float64, 0, i-trailStart)
		for j := trailStart; j < i; j++ {
			synHist = append(synHist, float64(windows[j].Stats.CntSYN))
		}

		synAck := float64(stats.CntSYN) / math.Max(float64(stats.CntACK), 1)

		var avgSyn float64
		if i >= windowCount {
			for j := i - windowCount; j < i; j++ {
				avgSyn += float64(windows[j].Stats.CntSYN)
			}
			avgSyn /= float64(windowCount)
		}

		synSpikeLegacy := (avgSyn > 0 && float64(stats.CntSYN) > avgSyn*synHistoricRatio) ||
			(avgSyn == 0 && stats.CntSYN > synThreshold)

		synAdaptive := false
		if len(synHist) >= minStatSample {
			if z, ok := zScore(float64(stats.CntSYN), synHist); ok && z > zStrong {
				synAdaptive = true
			}
		}

		synVolume := stats.CntSYN > synThreshold || synAdaptive
		if !synVolume {
			continue
		}
		if synAck <= synAckRatio {
			continue
		}

		synPerIP := 0.0
		if stats.UniqueSrcIPs > 0 {
			synPerIP = float64(stats.CntSYN) / float64(stats.UniqueSrcIPs)
		}

		if synSpikeLegacy || synAdaptive {
			if synPerIP > 0 && synPerIP < synPerIPThreshold {
				anomalous = append(anomalous, windowElement)
				continue
			}
		}
	}
	ewmaBPSLogFlush()
	return anomalous
}

func unionTimeWindows(a, b []packet.TimeWindow) []packet.TimeWindow {
	seen := make(map[int64]struct{})
	out := make([]packet.TimeWindow, 0, len(a)+len(b))
	for _, w := range a {
		k := w.StartTime.UnixNano()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, w)
	}
	for _, w := range b {
		k := w.StartTime.UnixNano()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, w)
	}
	return out
}

// sourceAugmentedWindows — reflection/amplification (упрощённо) и MAD по PPS среди источников;
// помечает окна с высоким BPS или SYN, пересекающиеся по времени с «акторами».
func (d *DDoSDetector) sourceAugmentedWindows(windows []packet.TimeWindow, flows map[string]*packet.FlowInfo, captureDuration time.Duration) []packet.TimeWindow {
	const (
		bpsGate    = 1_000_000
		synGate    = 1000
		madCoeff   = 0.6745
		madZStrong = 3.5
		minSources = 10 // MinSourcesForAdaptation из PDF (агрегация по источникам)
	)

	sources := packet.AggregateBySource(flows, captureDuration)
	if len(sources) == 0 {
		return nil
	}

	actorFlows := make(map[string]struct{}) // flowID

	// --- Amplification: много источников с ровно одним DstIP, часть — UDP на порт усилителя ---
	victimCounts := make(map[string][]string) // victim -> list of src IPs
	srcSingleDst := singleDstIPBySource(flows)
	for src, victim := range srcSingleDst {
		victimCounts[victim] = append(victimCounts[victim], src)
	}
	for _, srcs := range victimCounts {
		if len(srcs) < minAmplificationActors {
			continue
		}
		udpAmp := 0
		for _, src := range srcs {
			if sourceHasAmplifierUDPFlow(flows, src) {
				udpAmp++
			}
		}
		if udpAmp < minAmplificationUDP {
			continue
		}
		for _, src := range srcs {
			addFlowsForSource(flows, src, actorFlows)
		}
	}

	// --- MAD по PPS среди источников (исключая текущий из baseline) ---
	if len(sources) >= minSources {
		ppsAll := make([]float64, len(sources))
		for i := range sources {
			ppsAll[i] = sources[i].PPS
		}
		for i := range sources {
			others := make([]float64, 0, len(sources)-1)
			for j := range sources {
				if j == i {
					continue
				}
				others = append(others, ppsAll[j])
			}
			if len(others) < minStatSample {
				continue
			}
			if zm, ok := madHighScore(ppsAll[i], others, madCoeff); ok && zm > madZStrong {
				addFlowsForSource(flows, sources[i].SourceIP, actorFlows)
			}
		}
	}

	if len(actorFlows) == 0 {
		return nil
	}

	var out []packet.TimeWindow
	for _, w := range windows {
		st := w.Stats
		if st.BPS <= bpsGate && st.CntSYN <= synGate {
			continue
		}
		for flowID := range actorFlows {
			f := flows[flowID]
			if f == nil {
				continue
			}
			if flowIntersectsWindow(f, w) {
				out = append(out, w)
				break
			}
		}
	}
	return out
}

func flowIntersectsWindow(f *packet.FlowInfo, w packet.TimeWindow) bool {
	for _, p := range f.Packets {
		if !p.Timestamp.Before(w.StartTime) && p.Timestamp.Before(w.EndTime) {
			return true
		}
	}
	return false
}

func addFlowsForSource(flows map[string]*packet.FlowInfo, srcIP string, out map[string]struct{}) {
	for id, f := range flows {
		s := f.SourceIP
		if s == "" && len(f.Packets) > 0 {
			s = f.Packets[0].SrcIP
		}
		if s == srcIP {
			out[id] = struct{}{}
		}
	}
}

func sourceHasAmplifierUDPFlow(flows map[string]*packet.FlowInfo, srcIP string) bool {
	for _, f := range flows {
		s := f.SourceIP
		if s == "" && len(f.Packets) > 0 {
			s = f.Packets[0].SrcIP
		}
		if s != srcIP {
			continue
		}
		if f.Protocol != "UDP" {
			continue
		}
		portStr := f.DestPort
		if portStr == "" && len(f.Packets) > 0 {
			portStr = f.Packets[0].DstPort
		}
		p, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		if _, ok := amplificationUDPPorts[p]; ok {
			return true
		}
	}
	return false
}

// singleDstIPBySource: для каждого SrcIP ровно один уникальный DstIP по всем потокам.
func singleDstIPBySource(flows map[string]*packet.FlowInfo) map[string]string {
	type pair struct{}
	srcDst := make(map[string]map[string]struct{})
	for _, f := range flows {
		src := f.SourceIP
		if src == "" && len(f.Packets) > 0 {
			src = f.Packets[0].SrcIP
		}
		dst := f.DestinationIP
		if dst == "" && len(f.Packets) > 0 {
			dst = f.Packets[0].DstIP
		}
		if src == "" || dst == "" {
			continue
		}
		if srcDst[src] == nil {
			srcDst[src] = make(map[string]struct{})
		}
		srcDst[src][dst] = struct{}{}
	}
	out := make(map[string]string)
	for src, set := range srcDst {
		if len(set) == 1 {
			for d := range set {
				out[src] = d
			}
		}
	}
	return out
}

// totalRST – вспомогательная функция для подсчёта RST во всех окнах
func totalRST(windows []packet.TimeWindow) int {
	total := 0
	for _, w := range windows {
		total += w.Stats.CntRST
	}
	return total
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func sampleStdDev(xs []float64) (float64, bool) {
	if len(xs) < 2 {
		return 0, false
	}
	m := mean(xs)
	var ss float64
	for _, x := range xs {
		d := x - m
		ss += d * d
	}
	v := ss / float64(len(xs)-1)
	if v < 1e-18 {
		return 0, false
	}
	return math.Sqrt(v), true
}

func zScore(current float64, history []float64) (float64, bool) {
	if len(history) < minStatSample {
		return 0, false
	}
	sd, ok := sampleStdDev(history)
	if !ok {
		return 0, false
	}
	mu := mean(history)
	return (current - mu) / sd, true
}

func percentileLinear(sorted []float64, p float64) float64 {
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

func tukeyHighOutlier(current float64, history []float64, k float64) bool {
	if len(history) < minStatSample {
		return false
	}
	xs := append([]float64(nil), history...)
	sort.Float64s(xs)
	q1 := percentileLinear(xs, 25)
	q3 := percentileLinear(xs, 75)
	iq := q3 - q1
	fence := q3 + k*iq
	return current > fence
}

func median(xs []float64) float64 {
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

// madHighScore — робастный «верхний» z по MAD (коэффициент 0.6745 как в ТЗ); порог |z|>3.5, здесь только верхний хвост.
func madHighScore(x float64, history []float64, madK float64) (float64, bool) {
	if len(history) < minStatSample {
		return 0, false
	}
	med := median(history)
	devs := make([]float64, len(history))
	for i, v := range history {
		devs[i] = math.Abs(v - med)
	}
	mad := median(devs)
	if mad < 1e-12 {
		return 0, false
	}
	return madK * (x - med) / mad, true
}
