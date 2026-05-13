package packet

import "time"

// SourceStats — агрегированная статистика по source IP.
// Группирует все потоки (FlowInfo), исходящие от одного IP-адреса,
// и вычисляет суммарные/средние метрики.
// По аналогии с WindowStats (агрегация по временным окнам),
// но ключом группировки является IP источника.
type SourceStats struct {
	SourceIP string

	TotalFlows   int // Количество потоков от данного IP
	TotalPackets int // Суммарное количество пакетов по всем потокам
	TotalBytes   int // Суммарный объём (байт) по всем потокам

	UniqueDstIPs   int // Уникальные IP назначения
	UniqueDstPorts int // Уникальные порты назначения

	SYNCount int // Суммарное количество SYN-флагов
	RSTCount int // Суммарное количество RST-флагов

	AvgFlowDuration   float64 // Средняя длительность потока (секунды)
	AvgPacketsPerFlow float64 // Среднее количество пакетов на поток

	PPS float64 // Packets per second (суммарно по всем потокам)
	BPS float64 // Bytes per second (суммарно по всем потокам)

	// Дополнительная статистика (полезна для детекторов)
	ACKCount int
	FINCount int
	PSHCount int
	URGCount int

	// Внутренние множества для подсчёта уникальных значений (не экспортируются)
	dstIPSet   map[string]struct{}
	dstPortSet map[string]struct{}
}

// newSourceStats создаёт новый SourceStats для данного IP
func newSourceStats(sourceIP string) *SourceStats {
	return &SourceStats{
		SourceIP:   sourceIP,
		dstIPSet:   make(map[string]struct{}),
		dstPortSet: make(map[string]struct{}),
	}
}

// addFlow добавляет данные одного потока в агрегированную статистику
func (ss *SourceStats) addFlow(flow *FlowInfo) {
	ss.TotalFlows++
	ss.TotalPackets += flow.Stats.CntPackets
	ss.TotalBytes += flow.Stats.FlowLength

	ss.SYNCount += flow.Stats.CntSYN
	ss.RSTCount += flow.Stats.CntRST
	ss.ACKCount += flow.Stats.CntACK
	ss.FINCount += flow.Stats.CntFIN
	ss.PSHCount += flow.Stats.CntPSH
	ss.URGCount += flow.Stats.CntURG

	// Собираем уникальные dst IP и порты
	dstIP := flow.Stats.DstIP
	if dstIP == "" {
		dstIP = flow.DestinationIP
	}
	dstPort := flow.Stats.DstPort
	if dstPort == "" {
		dstPort = flow.DestPort
	}

	if dstIP != "" {
		ss.dstIPSet[dstIP] = struct{}{}
	}
	if dstPort != "" {
		ss.dstPortSet[dstPort] = struct{}{}
	}
}

// finalize вычисляет итоговые средние значения и PPS/BPS
func (ss *SourceStats) finalize(totalDuration time.Duration) {
	ss.UniqueDstIPs = len(ss.dstIPSet)
	ss.UniqueDstPorts = len(ss.dstPortSet)

	if ss.TotalFlows > 0 {
		ss.AvgPacketsPerFlow = float64(ss.TotalPackets) / float64(ss.TotalFlows)
	}

	seconds := totalDuration.Seconds()
	if seconds > 0 {
		ss.PPS = float64(ss.TotalPackets) / seconds
		ss.BPS = float64(ss.TotalBytes) / seconds
	}

	// Освобождаем внутренние множества
	ss.dstIPSet = nil
	ss.dstPortSet = nil
}

// AggregateBySource группирует проанализированные потоки по source IP
// и вычисляет агрегированную статистику для каждого IP.
// Потоки (flows) должны быть предварительно проанализированы через AnalyzeFlow().
//
// totalDuration — общая длительность захвата (для вычисления PPS/BPS).
// Если равна 0 или неизвестна, можно передать разницу между
// первым и последним пакетом.
func AggregateBySource(flows map[string]*FlowInfo, totalDuration time.Duration) []SourceStats {
	byIP := make(map[string]*SourceStats)

	var totalFlowDurationSumByIP = make(map[string]float64)

	for _, flow := range flows {
		srcIP := flow.Stats.SrcIP
		if srcIP == "" {
			srcIP = flow.SourceIP
		}
		if srcIP == "" && len(flow.Packets) > 0 {
			srcIP = flow.Packets[0].SrcIP
		}
		if srcIP == "" {
			continue
		}

		if byIP[srcIP] == nil {
			byIP[srcIP] = newSourceStats(srcIP)
		}
		byIP[srcIP].addFlow(flow)
		totalFlowDurationSumByIP[srcIP] += flow.Stats.Duration.Seconds()
	}

	results := make([]SourceStats, 0, len(byIP))
	for ip, ss := range byIP {
		ss.finalize(totalDuration)

		// Средняя длительность потока
		if ss.TotalFlows > 0 {
			ss.AvgFlowDuration = totalFlowDurationSumByIP[ip] / float64(ss.TotalFlows)
		}

		results = append(results, *ss)
	}

	return results
}

// AggregateBySourceFromSlice — то же самое, что AggregateBySource,
// но принимает слайс потоков вместо map.
// Удобно для использования вне основного пайплайна.
func AggregateBySourceFromSlice(flows []*FlowInfo, totalDuration time.Duration) []SourceStats {
	flowMap := make(map[string]*FlowInfo, len(flows))
	for _, f := range flows {
		flowMap[f.FlowID] = f
	}
	return AggregateBySource(flowMap, totalDuration)
}
