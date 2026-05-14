package main

import (
	"analizier/backend/src/parser"
	"analizier/src/detector"
	pkt "analizier/src/packet"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// ------------------------------------------------------------
// Вспомогательные функции
// ------------------------------------------------------------

func ExportFlowsToCSV(filename string, flows map[string]*pkt.FlowInfo) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"FlowID", "Packets", "TotalBytes", "AvgSize", "StdDevSize",
		"BPS", "IAT_ms", "Duration_s", "SYN", "ACK", "FIN", "PSH", "RST", "URG",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for id, info := range flows {
		s := info.Stats
		record := []string{
			id,
			strconv.Itoa(s.CntPackets),
			strconv.Itoa(s.FlowLength),
			fmt.Sprintf("%.2f", s.AvgPacketSize),
			fmt.Sprintf("%.2f", s.StdDevPacketSize),
			fmt.Sprintf("%.2f", s.BPS),
			fmt.Sprintf("%d", s.IAT.Milliseconds()),
			fmt.Sprintf("%.4f", s.Duration.Seconds()),
			strconv.Itoa(s.CntSYN),
			strconv.Itoa(s.CntACK),
			strconv.Itoa(s.CntFIN),
			strconv.Itoa(s.CntPSH),
			strconv.Itoa(s.CntRST),
			strconv.Itoa(s.CntURG),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func DivideByFlow(packets []pkt.PacketInfo) map[string]*pkt.FlowInfo {
	flows := make(map[string]*pkt.FlowInfo)
	for _, packet := range packets {
		flowID := pkt.GetBiFlowID(packet)
		if flows[flowID] == nil {
			flows[flowID] = &pkt.FlowInfo{}
		}
		curFlow := flows[flowID]
		curFlow.FlowID = flowID
		curFlow.Packets = append(curFlow.Packets, packet)
	}
	return flows
}

func ExportWindowsToCSV(filename string, windows []pkt.TimeWindow) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"StartTime", "EndTime",
		"TotalPackets", "TotalBytes",
		"PPS", "BPS",
		"UniqueSrcIPs", "UniqueDstIPs",
		"UniqueSrcPorts", "UniqueDstPorts",
		"ActiveFlows",
		"CntSYN", "CntACK", "CntFIN", "CntRST", "CntPSH", "CntURG",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("error writing header: %v", err)
	}

	for _, w := range windows {
		s := w.Stats
		record := []string{
			w.StartTime.Format("2006-01-02 15:04:05.000"),
			w.EndTime.Format("15:04:05.000"),
			strconv.Itoa(s.TotalPackets),
			strconv.Itoa(s.TotalBytes),
			fmt.Sprintf("%.2f", s.PPS),
			fmt.Sprintf("%.2f", s.BPS),
			strconv.Itoa(s.UniqueSrcIPs),
			strconv.Itoa(s.UniqueDstIPs),
			strconv.Itoa(s.UniqueSrcPorts),
			strconv.Itoa(s.UniqueDstPorts),
			strconv.Itoa(s.ActiveFlows),
			strconv.Itoa(s.CntSYN),
			strconv.Itoa(s.CntACK),
			strconv.Itoa(s.CntFIN),
			strconv.Itoa(s.CntRST),
			strconv.Itoa(s.CntPSH),
			strconv.Itoa(s.CntURG),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("error writing record: %v", err)
		}
	}
	return nil
}

func flowIntersectsTimeWindow(f *pkt.FlowInfo, w pkt.TimeWindow) bool {
	for _, p := range f.Packets {
		t := p.Timestamp
		if !t.Before(w.StartTime) && t.Before(w.EndTime) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------
// Основная функция
// ------------------------------------------------------------
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <pcap_file>")
		return
	}
	filename := os.Args[1]

	p := parser.NewParser()
	packets := p.Parse(filename)

	windows := pkt.SplitIntoWindows(packets, 10*time.Second)

	flows := DivideByFlow(packets)
	for _, flow := range flows {
		pkt.AnalyzeFlow(flow)
	}

	// ===== Статистика =====
	fmt.Println("==================== СТАТИСТИКА ====================")
	fmt.Printf("Файл: %s\n", filename)
	fmt.Printf("Всего пакетов: %d\n", len(packets))
	fmt.Printf("Временных окон: %d\n", len(windows))
	fmt.Printf("Всего потоков: %d\n", len(flows))

	if len(windows) > 0 {
		fmt.Println("\n--- Временные окна ---")
		for i, win := range windows {
			s := win.Stats
			fmt.Printf("  [%d] %s – %s | PPS=%.0f | BPS=%.0f | Пакетов=%d | Байт=%d\n",
				i+1,
				win.StartTime.Format("15:04:05"),
				win.EndTime.Format("15:04:05"),
				s.PPS, s.BPS, s.TotalPackets, s.TotalBytes)
		}
	}

	// Топ-5 потоков по количеству пакетов
	if len(flows) > 0 {
		fmt.Println("\n--- Топ-5 потоков по пакетам ---")
		type flowEntry struct {
			id   string
			flow *pkt.FlowInfo
		}
		sorted := make([]flowEntry, 0, len(flows))
		for id, flow := range flows {
			sorted = append(sorted, flowEntry{id, flow})
		}
		for i := 0; i < len(sorted); i++ {
			for j := i + 1; j < len(sorted); j++ {
				if sorted[j].flow.Stats.CntPackets > sorted[i].flow.Stats.CntPackets {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}
		for i := 0; i < 5 && i < len(sorted); i++ {
			f := sorted[i]
			fmt.Printf("  %s | %s:%s → %s:%s | Пакетов=%d | BPS=%.0f | SYN=%d RST=%d\n",
				f.id,
				f.flow.Packets[0].SrcIP, f.flow.Packets[0].SrcPort,
				f.flow.Packets[0].DstIP, f.flow.Packets[0].DstPort,
				f.flow.Stats.CntPackets, f.flow.Stats.BPS,
				f.flow.Stats.CntSYN, f.flow.Stats.CntRST)
		}
	}

	// ----- DDoS детекция -----
	ddosDet := &detector.DDoSDetector{}
	var capDur time.Duration
	if len(packets) >= 2 {
		capDur = packets[len(packets)-1].Timestamp.Sub(packets[0].Timestamp)
	}
	anomalousWindows := ddosDet.AnalyzeWindowsWithFlows(windows, flows, capDur)

	dosFlowIDs := make(map[string]bool)
	for _, win := range anomalousWindows {
		for flowID, flow := range flows {
			if len(flow.Packets) == 0 {
				continue
			}
			if flowIntersectsTimeWindow(flow, win) {
				dosFlowIDs[flowID] = true
			}
		}
	}
	dosCount := len(dosFlowIDs)

	fmt.Println("\n==================== DDoS ДЕТЕКЦИЯ ====================")
	fmt.Printf("Аномальных окон: %d\n", len(anomalousWindows))
	for _, win := range anomalousWindows {
		s := win.Stats
		ratio := float64(s.CntRST) / float64(s.CntSYN+1)
		fmt.Printf("  %s – %s | BPS=%.0f | PPS=%.0f | SYN=%d | RST=%d | RST/SYN=%.2f | UniqueDstPorts=%d\n",
			win.StartTime.Format("15:04:05"), win.EndTime.Format("15:04:05"),
			s.BPS, s.PPS, s.CntSYN, s.CntRST, ratio, s.UniqueDstPorts)
	}
	fmt.Printf("Потоков DoS: %d\n", dosCount)

	// ----- Детекция червей -----
	suspiciousPorts := []int{445, 139, 1433, 6881, 25}
	_, internalNet, _ := net.ParseCIDR("59.166.0.0/16")
	wormDet := detector.NewWormDetector(200, 100_000, internalNet)

	wormCount := 0
	for _, flow := range flows {
		dstPort, _ := strconv.Atoi(flow.Stats.DstPort)
		isSuspicious := false
		for _, p := range suspiciousPorts {
			if dstPort == p {
				isSuspicious = true
				break
			}
		}
		if isSuspicious {
			res := wormDet.Analyze(flow.Stats)
			if res.IsAnomaly {
				wormCount++
				fmt.Printf("  [ЧЕРВЬ] %s | dstPort=%d | Пакетов=%d | BPS=%.0f\n",
					flow.FlowID, dstPort, flow.Stats.CntPackets, flow.Stats.BPS)
			}
		}
	}
	fmt.Println("\n==================== ДЕТЕКЦИЯ ЧЕРВЕЙ ====================")
	fmt.Printf("Потоков-червей: %d\n", wormCount)

	// ----- Детектор перегрузки -----
	overloadDet := detector.NewAdaptiveOverloadDetector(10, 2.7)
	overloadWindows := overloadDet.AnalyzeWindows(windows)

	fmt.Println("\n==================== ПЕРЕГРУЗКА ====================")
	fmt.Printf("Окон перегрузки: %d\n", len(overloadWindows))
	for _, w := range overloadWindows {
		fmt.Printf("  %s – %s | BPS=%.0f | PPS=%.0f\n",
			w.StartTime.Format("15:04:05"), w.EndTime.Format("15:04:05"),
			w.Stats.BPS, w.Stats.PPS)
	}

	// ----- Детектор вирусной активности -----
	whitelist := []string{}
	virusDet := detector.NewVirusDetector(whitelist)

	virusCount := 0
	for _, flow := range flows {
		res := virusDet.Analyze(flow.Stats)
		if res.IsAnomaly {
			virusCount++
			fmt.Printf("  [ВИРУС] %s | dstIP=%s | dstPort=%s | Пакетов=%d | BPS=%.0f\n",
				flow.FlowID, flow.Stats.DstIP, flow.Stats.DstPort,
				flow.Stats.CntPackets, flow.Stats.BPS)
		}
	}
	fmt.Println("\n==================== ВИРУСНАЯ АКТИВНОСТЬ ====================")
	fmt.Printf("Потоков с вирусами: %d\n", virusCount)

	fmt.Println("\n======================================================")
	fmt.Println("Анализ завершён")
}
