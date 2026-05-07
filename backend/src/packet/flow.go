package packet

import (
    "math"
    "time"
)

type TLSInfo struct {
    JA3 string // отпечаток клиента TLS
    SNI string // имя сервера из ClientHello
}

type FlowInfo struct {
    FlowID        string
    Interface     string
    StartTime     time.Time
    EndTime       time.Time
    TrafficVolume int
    SourceIP      string
    DestinationIP string
    IPVersion     string
    SourcePort    string
    DestPort      string
    Length        int
    Statuses      []string
    Packets       []PacketInfo
    Stats         FlowStats
}

type FlowStats struct {
    CntPackets       int
    FlowLength       int
    AvgPacketSize    float64
    StdDevPacketSize float64
    BPS              float64 // Bytes per Second
    IAT              time.Duration
    Duration         time.Duration
    CntSYN           int
    CntACK           int
    CntFIN           int
    CntPSH           int
    CntRST           int
    CntURG           int
    SrcIP            string
    DstIP            string
    SrcPort          string
    DstPort          string
    TLS              *TLSInfo
}

func CalculateStdDev(lengths []int) float64 {
	n := len(lengths)
	if n == 0 {
		return 0
	}

	var sum float64
	for _, l := range lengths {
		sum += float64(l)
	}
	mean := sum / float64(n)

	var squaredDiffSum float64
	for _, l := range lengths {
		diff := float64(l) - mean
		squaredDiffSum += diff * diff
	}

	variance := squaredDiffSum / float64(n)

	return math.Sqrt(variance)
}

func CalculateDuration(flow *FlowInfo) time.Duration {
	if len(flow.Packets) < 2 {
		return 0
	}
	first := flow.Packets[0].Timestamp
	last := flow.Packets[len(flow.Packets)-1].Timestamp
	return last.Sub(first)
}

func CalculateBPS(duration time.Duration, totalBytes int) float64 {
	seconds := duration.Seconds()

	if seconds <= 0 {
		return float64(totalBytes)
	}

	return float64(totalBytes) / seconds
}

func CalculateIAT(duration time.Duration, cnt int) time.Duration {
	if cnt <= 1 {
		return 0
	}
	return time.Duration(int(duration) / (cnt - 1))
}

func CalculateFlags(flow *FlowStats, flags []string) {
	for _, flag := range flags {
		switch flag {
		case "SYN":
			flow.CntSYN++
		case "ACK":
			flow.CntACK++
		case "FIN":
			flow.CntFIN++
		case "PSH":
			flow.CntPSH++
		case "RST":
			flow.CntRST++
		case "URG":
			flow.CntURG++
		}
	}
}

func AnalyzeFlow(flow *FlowInfo) {
    existingTLS := flow.Stats.TLS
    
    stat := FlowStats{}
    var lengths []int
    for _, packet := range flow.Packets {
        stat.FlowLength += packet.Length
        lengths = append(lengths, packet.Length)
        CalculateFlags(&stat, packet.Flags)
    }
    stat.CntPackets = len(flow.Packets)
    stat.AvgPacketSize = float64(stat.FlowLength) / float64(stat.CntPackets)
    stat.StdDevPacketSize = CalculateStdDev(lengths)
    stat.Duration = CalculateDuration(flow)
    stat.BPS = CalculateBPS(stat.Duration, stat.FlowLength)
    stat.IAT = CalculateIAT(stat.Duration, stat.CntPackets)
    stat.SrcIP = flow.SourceIP
    stat.DstIP = flow.DestinationIP
    stat.SrcPort = flow.SourcePort
    stat.DstPort = flow.DestPort
    
    // Восстанавливаем TLS
    stat.TLS = existingTLS
    
    flow.Stats = stat
}
