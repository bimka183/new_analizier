package detector

import (
	"analizier/backend/src/packet"
	"fmt"
	"testing"
	"time"
)

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

func TestAnalyzeWindows_FiltersWhenTotalRSTTooLow(t *testing.T) {
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
		// totalRST must be > 10 to pass the early return.
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
		// totalRST must be > 10. Also BPS must be > 1_000_000.
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
		// Ensure totalRST > 10 so the detector doesn't short-circuit.
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
				// Required gates.
				BPS: 2_000_000,
				// Ensure totalRST > 10 overall.
				CntRST: 11,
				// SYN flood condition.
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
