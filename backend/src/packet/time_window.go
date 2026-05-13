package packet

import (
	"fmt"
	"time"
)

type TimeWindow struct {
	StartTime time.Time
	EndTime   time.Time
	Stats     WindowStats

	// TLS-счётчики для детектора перегрузки
	ClientHelloCount     float64 // Текущее количество TLS ClientHello в окне
	ClientHelloCountPrev float64 // Количество в предыдущем окне (заполняется детектором)
}

type WindowStats struct {
	TotalPackets int
	TotalBytes   int
	PPS          float64
	BPS          float64

	UniqueSrcIPs   int
	UniqueDstIPs   int
	UniqueSrcPorts int
	UniqueDstPorts int
	ActiveFlows    int

	CntSYN int
	CntACK int
	CntFIN int
	CntRST int
	CntPSH int
	CntURG int

	// TLS-счётчик
	TLSFlowCount int

	srcIPSet   map[string]struct{}
	dstIPSet   map[string]struct{}
	srcPortSet map[string]struct{}
	dstPortSet map[string]struct{}
	flowSet    map[string]struct{}
}

func NewTimeWindow(start, end time.Time) TimeWindow {
	return TimeWindow{
		StartTime: start,
		EndTime:   end,
		Stats: WindowStats{
			srcIPSet:   make(map[string]struct{}),
			dstIPSet:   make(map[string]struct{}),
			srcPortSet: make(map[string]struct{}),
			dstPortSet: make(map[string]struct{}),
			flowSet:    make(map[string]struct{}),
		},
	}
}

func GetBiFlowID(p PacketInfo) string {
	if p.SrcIP < p.DstIP {
		return fmt.Sprintf("%s:%s-%s:%s", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
	}
	return fmt.Sprintf("%s:%s-%s:%s", p.DstIP, p.DstPort, p.SrcIP, p.SrcPort)
}

func (w *TimeWindow) AddPacket(p PacketInfo) {
	w.Stats.TotalPackets++
	w.Stats.TotalBytes += p.Length

	w.Stats.srcIPSet[p.SrcIP] = struct{}{}
	w.Stats.dstIPSet[p.DstIP] = struct{}{}
	w.Stats.srcPortSet[p.SrcPort] = struct{}{}
	w.Stats.dstPortSet[p.DstPort] = struct{}{}

	flowID := GetBiFlowID(p)
	w.Stats.flowSet[flowID] = struct{}{}

	for _, flag := range p.Flags {
		switch flag {
		case "SYN":
			w.Stats.CntSYN++
		case "ACK":
			w.Stats.CntACK++
		case "FIN":
			w.Stats.CntFIN++
		case "RST":
			w.Stats.CntRST++
		case "PSH":
			w.Stats.CntPSH++
		case "URG":
			w.Stats.CntURG++
		}
	}
}

func (w *TimeWindow) Finalize(interval time.Duration) {
	w.Stats.UniqueSrcIPs = len(w.Stats.srcIPSet)
	w.Stats.UniqueDstIPs = len(w.Stats.dstIPSet)
	w.Stats.UniqueSrcPorts = len(w.Stats.srcPortSet)
	w.Stats.UniqueDstPorts = len(w.Stats.dstPortSet)
	w.Stats.ActiveFlows = len(w.Stats.flowSet)

	seconds := interval.Seconds()
	if seconds > 0 {
		w.Stats.PPS = float64(w.Stats.TotalPackets) / seconds
		w.Stats.BPS = float64(w.Stats.TotalBytes) / seconds
	}

	w.Stats.srcIPSet = nil
	w.Stats.dstIPSet = nil
	w.Stats.dstPortSet = nil
	w.Stats.flowSet = nil
}

func SplitIntoWindows(packets []PacketInfo, interval time.Duration) []TimeWindow {
	if len(packets) == 0 {
		return nil
	}

	var windows []TimeWindow

	start := packets[0].Timestamp.Truncate(interval)
	currentWindow := NewTimeWindow(start, start.Add(interval))

	for _, p := range packets {
		for p.Timestamp.After(currentWindow.EndTime) || p.Timestamp.Equal(currentWindow.EndTime) {
			currentWindow.Finalize(interval)
			windows = append(windows, currentWindow)

			start = currentWindow.EndTime
			currentWindow = NewTimeWindow(start, start.Add(interval))
		}

		currentWindow.AddPacket(p)
	}

	currentWindow.Finalize(interval)
	windows = append(windows, currentWindow)

	return windows
}
