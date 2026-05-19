package detector

import (
	"analizier/backend/src/packet"
	"fmt"
	"math"
	"sort"
	"testing"
	"time"
)

func Test_aggregateBySource_PPS(t *testing.T) {
	flows := map[string]*packet.FlowInfo{
		"a": {SourceIP: "10.0.0.1", Packets: make([]packet.PacketInfo, 100)},
		"b": {SourceIP: "10.0.0.1", Packets: make([]packet.PacketInfo, 50)},
		"c": {SourceIP: "10.0.0.2", Packets: make([]packet.PacketInfo, 10)},
	}
	cap := 10 * time.Second
	got := aggregateBySource(flows, cap)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 distinct sources", len(got))
	}
	sort.Slice(got, func(i, j int) bool { return got[i].SourceIP < got[j].SourceIP })
	want1 := 150.0 / cap.Seconds()
	want2 := 10.0 / cap.Seconds()
	if got[0].SourceIP != "10.0.0.1" || math.Abs(got[0].PPS-want1) > 1e-9 {
		t.Fatalf("10.0.0.1: %+v want PPS=%g", got[0], want1)
	}
	if got[1].SourceIP != "10.0.0.2" || math.Abs(got[1].PPS-want2) > 1e-9 {
		t.Fatalf("10.0.0.2: %+v want PPS=%g", got[1], want2)
	}
}

func Test_aggregateBySource_emptyOrZeroDuration(t *testing.T) {
	if got := aggregateBySource(nil, time.Second); got != nil {
		t.Fatalf("nil flows: got %#v, want nil", got)
	}
	if got := aggregateBySource(map[string]*packet.FlowInfo{}, time.Second); got != nil {
		t.Fatalf("empty map: got %#v, want nil", got)
	}
	if got := aggregateBySource(map[string]*packet.FlowInfo{"x": {SourceIP: "1.1.1.1", Packets: []packet.PacketInfo{{}}}}, 0); got != nil {
		t.Fatalf("zero duration: got %#v, want nil", got)
	}
}

func Test_aggregateBySource_usesCntPacketsWhenNoPacketSlice(t *testing.T) {
	flows := map[string]*packet.FlowInfo{
		"x": {SourceIP: "192.168.0.5", Packets: nil, Stats: packet.FlowStats{CntPackets: 20}},
	}
	cap := 2 * time.Second
	got := aggregateBySource(flows, cap)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	want := 20.0 / cap.Seconds()
	if math.Abs(got[0].PPS-want) > 1e-9 {
		t.Fatalf("PPS = %g, want %g", got[0].PPS, want)
	}
}

func TestDDoSDetector_Name(t *testing.T) {
	d := &DDoSDetector{}
	if got, want := d.Name(), "DDoSDetector"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
}

func TestDDoSDetector_Analyze_ReturnsNotAnomaly(t *testing.T) {
	d := &DDoSDetector{}
	res := d.Analyze(packet.FlowStats{})
	if res.IsAnomaly {
		t.Fatalf("Analyze() returned anomaly: %+v", res)
	}
}

func Test_totalRST_SumsAcrossWindows(t *testing.T) {
	windows := []packet.TimeWindow{
		{Stats: packet.WindowStats{CntRST: 3}},
		{Stats: packet.WindowStats{CntRST: 7}},
		{Stats: packet.WindowStats{CntRST: 11}},
	}
	if got, want := totalRST(windows), 21; got != want {
		t.Fatalf("totalRST() = %d, want %d", got, want)
	}
}

func TestAnalyzeWindows_NoSpuriousWhenHighBpsButQuietSignals(t *testing.T) {
	d := &DDoSDetector{}
	windows := []packet.TimeWindow{
		{Stats: packet.WindowStats{BPS: 2_000_000, CntSYN: 10, CntRST: 10}},
	}
	if got := d.AnalyzeWindows(windows); len(got) != 0 {
		t.Fatalf("AnalyzeWindows() returned %d anomalous windows, want 0", len(got))
	}
}

func TestAnalyzeWindows_FiltersWhenBPSBelowThreshold(t *testing.T) {
	d := &DDoSDetector{}
	windows := []packet.TimeWindow{
		{Stats: packet.WindowStats{BPS: 1_000_000, CntSYN: 1, CntRST: 11}},
		{Stats: packet.WindowStats{BPS: 999_999, CntSYN: 1, CntRST: 0}},
	}
	if got := d.AnalyzeWindows(windows); len(got) != 0 {
		t.Fatalf("AnalyzeWindows() returned %d anomalous windows, want 0", len(got))
	}
}

func TestAnalyzeWindows_FlagsRSTSynRatioAnomaly(t *testing.T) {
	d := &DDoSDetector{}
	windows := []packet.TimeWindow{
		{Stats: packet.WindowStats{BPS: 2_000_000, CntSYN: 1, CntRST: 16}},
	}
	got := d.AnalyzeWindows(windows)
	if len(got) != 1 {
		t.Fatalf("AnalyzeWindows() returned %d anomalous windows, want 1", len(got))
	}
}

func TestAnalyzeWindows_FlagsUniqueDstPortsAnomaly(t *testing.T) {
	d := &DDoSDetector{}
	windows := []packet.TimeWindow{
		{Stats: packet.WindowStats{BPS: 2_000_000, UniqueDstPorts: 371, CntRST: 11}},
	}
	got := d.AnalyzeWindows(windows)
	if len(got) != 1 {
		t.Fatalf("AnalyzeWindows() returned %d anomalous windows, want 1", len(got))
	}
}

func TestAnalyzeWindows_FlagsSynFloodAnomaly(t *testing.T) {
	d := &DDoSDetector{}
	windows := []packet.TimeWindow{
		{
			Stats: packet.WindowStats{
				BPS:            2_000_000,
				CntRST:         11,
				CntSYN:         1500,
				CntACK:         0,
				UniqueSrcIPs:   600, // synPerIP = 2.5 (< 3.0)
				UniqueDstPorts: 1,
			},
		},
	}
	got := d.AnalyzeWindows(windows)
	if len(got) != 1 {
		t.Fatalf("AnalyzeWindows() returned %d anomalous windows, want 1", len(got))
	}
}

func TestAnalyzeWindowsWithFlows_AmplificationSingleVictim(t *testing.T) {
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	winEnd := start.Add(10 * time.Second)
	ts := start.Add(2 * time.Second)

	flows := make(map[string]*packet.FlowInfo)
	for i := 0; i < 10; i++ {
		srcIP := fmt.Sprintf("10.0.0.%d", i+1)
		id := fmt.Sprintf("flow-%d", i)
		f := &packet.FlowInfo{
			FlowID:        id,
			SourceIP:      srcIP,
			DestinationIP: "9.9.9.9",
			DestPort:      "53",
			Protocol:      "UDP",
			Packets: []packet.PacketInfo{{
				SrcIP: srcIP, DstIP: "9.9.9.9", SrcPort: "1111", DstPort: "53",
				Protocol: "UDP", Length: 80, Timestamp: ts,
			}},
		}
		packet.AnalyzeFlow(f)
		flows[id] = f
	}

	windows := []packet.TimeWindow{{
		StartTime: start,
		EndTime:   winEnd,
		Stats: packet.WindowStats{
			TotalBytes: 12_000_000,
			BPS:        1_200_000,
			CntSYN:     2000,
			CntRST:     5,
		},
	}}

	d := &DDoSDetector{}
	if got := d.AnalyzeWindows(windows); len(got) != 0 {
		t.Fatalf("AnalyzeWindows() without flows: want 0 anomalous, got %d", len(got))
	}
	capDur := 100 * time.Second
	got := d.AnalyzeWindowsWithFlows(windows, flows, capDur)
	if len(got) != 1 {
		t.Fatalf("AnalyzeWindowsWithFlows() = %d windows, want 1", len(got))
	}
}
