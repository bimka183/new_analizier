// detector/worm_detector_test.go
package detector

import (
	"analizier/backend/src/packet"
	"net"
	"testing"
	"time"
)

func TestWormDetector_Name(t *testing.T) {
	d := NewWormDetector(3, 500.0, nil)
	if got, want := d.Name(), "WormDetector"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
}

func TestWormDetector_Analyze_EmptyStats(t *testing.T) {
	d := NewWormDetector(3, 500.0, nil)
	res := d.Analyze(packet.FlowStats{})
	if res.IsAnomaly {
		t.Fatalf("empty stats should not be anomaly")
	}
}

func TestWormDetector_Analyze_NonSuspiciousPort(t *testing.T) {
	d := NewWormDetector(1, 0, nil)
	res := d.Analyze(packet.FlowStats{
		DstPort:    "80",
		CntPackets: 10,
		BPS:        1000,
	})
	if res.IsAnomaly {
		t.Fatalf("HTTP port should not trigger worm detection")
	}
}

func TestWormDetector_Analyze_LowVolume(t *testing.T) {
	d := NewWormDetector(5, 1000, nil)
	
	// Мало пакетов
	res := d.Analyze(packet.FlowStats{
		DstPort: "445", CntPackets: 2, BPS: 2000,
	})
	if res.IsAnomaly {
		t.Fatalf("low packet count should not trigger")
	}
	
	// Низкий BPS
	res = d.Analyze(packet.FlowStats{
		DstPort: "445", CntPackets: 10, BPS: 100,
	})
	if res.IsAnomaly {
		t.Fatalf("low BPS should not trigger")
	}
}

func TestWormDetector_Analyze_InternalNetwork(t *testing.T) {
	_, net, _ := net.ParseCIDR("192.168.0.0/16")
	d := NewWormDetector(1, 0, net)
	
	res := d.Analyze(packet.FlowStats{
		SrcIP: "10.0.0.1", DstIP: "192.168.1.100",
		DstPort: "445", CntPackets: 10, BPS: 2000,
	})
	if res.IsAnomaly {
		t.Fatalf("internal network should be ignored")
	}
}

func TestWormDetector_SuspiciousTraffic(t *testing.T) {
	d := NewWormDetector(3, 500, nil)
	res := d.Analyze(packet.FlowStats{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		DstPort: "445", CntPackets: 10, BPS: 2000,
	})
	
	if !res.IsAnomaly {
		t.Fatalf("suspicious port should be detected")
	}
	if res.Type != AnomalyWorm {
		t.Fatalf("wrong anomaly type: %v", res.Type)
	}
	if res.Confidence < 0.7 || res.Confidence > 0.75 {
		t.Fatalf("base confidence should be ~0.7, got %f", res.Confidence)
	}
}

func TestWormDetector_InfectionChain(t *testing.T) {
	d := NewWormDetector(3, 500, nil)
	
	// Заражаем хост
	res1 := d.Analyze(packet.FlowStats{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.100",
		DstPort: "445", CntPackets: 10, BPS: 2000,
	})
	
	// Заражённый сканирует
	res2 := d.Analyze(packet.FlowStats{
		SrcIP: "10.0.0.100", DstIP: "10.0.0.200",
		DstPort: "139", CntPackets: 10, BPS: 2000,
	})
	
	if !res1.IsAnomaly || !res2.IsAnomaly {
		t.Fatal("both should be anomalies")
	}
	
	// Цепочка заражения должна давать более высокую уверенность
	if res2.Confidence < 0.85 {
		t.Fatalf("infection chain confidence should be >= 0.85, got %f", res2.Confidence)
	}
	if res2.Confidence <= res1.Confidence {
		t.Fatalf("chain confidence (%f) should be > base (%f)", res2.Confidence, res1.Confidence)
	}
}

func TestWormDetector_ExpiredInfection(t *testing.T) {
	d := NewWormDetector(3, 500, nil)
	d.SetCorrelWindow(50 * time.Millisecond)
	
	// Заражаем
	d.Analyze(packet.FlowStats{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.100",
		DstPort: "445", CntPackets: 10, BPS: 2000,
	})
	
	// Ждём
	time.Sleep(100 * time.Millisecond)
	
	// Сканируем после истечения окна
	res := d.Analyze(packet.FlowStats{
		SrcIP: "10.0.0.100", DstIP: "10.0.0.200",
		DstPort: "139", CntPackets: 10, BPS: 2000,
	})
	
	if !res.IsAnomaly {
		t.Fatal("should still detect suspicious traffic")
	}
	if res.Confidence >= 0.85 {
		t.Fatalf("expired chain should have lower confidence, got %f", res.Confidence)
	}
}

func TestWormDetector_VictimsTracking(t *testing.T) {
	d := NewWormDetector(3, 500, nil)
	
	if d.GetVictimCount() != 0 {
		t.Fatal("initial count should be 0")
	}
	
	d.Analyze(packet.FlowStats{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.100",
		DstPort: "445", CntPackets: 10, BPS: 2000,
	})
	d.Analyze(packet.FlowStats{
		SrcIP: "10.0.0.2", DstIP: "10.0.0.200",
		DstPort: "139", CntPackets: 10, BPS: 2000,
	})
	
	if d.GetVictimCount() != 2 {
		t.Fatalf("victim count = %d, want 2", d.GetVictimCount())
	}
	
	active := d.GetActiveVictims()
	if len(active) != 2 {
		t.Fatalf("active victims = %d, want 2", len(active))
	}
}