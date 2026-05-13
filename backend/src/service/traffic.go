package service

import (
	"analizier/backend/src/detector"
	"analizier/backend/src/models"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	pkt "analizier/backend/src/packet"
	prs "analizier/backend/src/parser"
	"analizier/backend/src/repository"
)

// UploadSummary содержит агрегированные метрики по загруженному файлу,
// включая структурированную сводку угроз для отображения на круговых диаграммах UI.
type UploadSummary struct {
	Packets          int           `json:"packets"`
	Flows            int           `json:"flows"`
	BPSAvg           float64       `json:"bps_avg"`
	AvgPacketSizeAvg float64       `json:"avg_packet_size_avg"`
	IATmsAvg         float64       `json:"iat_ms_avg"`
	ThreatSummary    []ThreatEntry `json:"threat_summary"`
}

type ThreatEntry struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// ProgressUpdate — структура для SSE-обновлений прогресса
type ProgressUpdate struct {
	Phase    string `json:"phase"`
	Progress int    `json:"progress"`
}

func MapFlowToTraffic(flow *pkt.FlowInfo) models.Traffic {
	return models.Traffic{
		FlowID:          flow.FlowID,
		Interface:       flow.Interface,
		Timestamp:       flow.StartTime.Format("2006-01-02T15:04:05.000Z"), // ISO 8601 для Date.parse() в JS
		TrafficVolume:   flow.TrafficVolume,
		SourceIP:        flow.SourceIP,
		DestinationIP:   flow.DestinationIP,
		SourcePort:      flow.SourcePort,
		DestinationPort: flow.DestPort,
		IPVersion:       flow.IPVersion,
		Protocol:        flow.Protocol,
		Length:          flow.Length,
		Flags:           strings.Join(flow.Statuses, ","),
		// FlowStats
		Packets:          flow.Stats.CntPackets,
		FlowLength:       flow.Stats.FlowLength,
		AvgPacketSize:    flow.Stats.AvgPacketSize,
		StdDevPacketSize: flow.Stats.StdDevPacketSize,
		BPS:              flow.Stats.BPS,
		IATms:            float64(flow.Stats.IAT.Milliseconds()),
		DurationSec:      flow.Stats.Duration.Seconds(),
		CntSYN:           flow.Stats.CntSYN,
		CntACK:           flow.Stats.CntACK,
		CntFIN:           flow.Stats.CntFIN,
		CntPSH:           flow.Stats.CntPSH,
		CntRST:           flow.Stats.CntRST,
		CntURG:           flow.Stats.CntURG,
	}
}

func divideByFlow(packets []pkt.PacketInfo) map[string]*pkt.FlowInfo {
	flows := make(map[string]*pkt.FlowInfo)
	for _, packet := range packets {
		flowID := pkt.GetBiFlowID(packet)
		if flows[flowID] == nil {
			flows[flowID] = &pkt.FlowInfo{
				FlowID:        flowID,
				Interface:     packet.Interface,
				StartTime:     packet.Timestamp,
				SourceIP:      packet.SrcIP,
				DestinationIP: packet.DstIP,
				IPVersion:     packet.IPVersion,
				Protocol:      packet.Protocol,
				SourcePort:    packet.SrcPort,
				DestPort:      packet.DstPort,
				Statuses:      make([]string, 0),
			}
		}
		curFlow := flows[flowID]
		curFlow.Packets = append(curFlow.Packets, packet)
		curFlow.EndTime = packet.Timestamp
		curFlow.TrafficVolume += packet.Length
		curFlow.Length += 1
		for _, flag := range packet.Flags {
			if !contains(curFlow.Statuses, flag) {
				curFlow.Statuses = append(curFlow.Statuses, flag)
			}
		}
	}
	return flows
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

type TrafficService struct {
	detectors     []detector.Detector
	flowDetectors []detector.FlowDetector
	repo          repository.TrafficRepository
	broadcast     chan models.Traffic

	// SSE progress channels: uploadID -> channel
	mu               sync.RWMutex
	progressChannels map[uint]chan ProgressUpdate
}

func NewTrafficService(
	repo repository.TrafficRepository,
	detectors []detector.Detector,
	flowDetectors []detector.FlowDetector,
	broadcast chan models.Traffic,
) *TrafficService {
	return &TrafficService{
		repo:             repo,
		detectors:        detectors,
		flowDetectors:    flowDetectors,
		broadcast:        broadcast,
		progressChannels: make(map[uint]chan ProgressUpdate),
	}
}

// RegisterProgress создаёт канал для SSE-подписки на прогресс загрузки.
func (s *TrafficService) RegisterProgress(uploadID uint) chan ProgressUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.progressChannels[uploadID]; ok {
		return existing
	}
	ch := make(chan ProgressUpdate, 20)
	s.progressChannels[uploadID] = ch
	return ch
}

// UnregisterProgress удаляет канал прогресса из карты.
func (s *TrafficService) UnregisterProgress(uploadID uint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.progressChannels, uploadID)
}

func (s *TrafficService) sendProgress(uploadID uint, phase string, progress int) {
	s.mu.RLock()
	ch, ok := s.progressChannels[uploadID]
	s.mu.RUnlock()

	if ok {
		select {
		case ch <- ProgressUpdate{Phase: phase, Progress: progress}:
		default:
		}
	}
}

// analyzeFile выполняет парсинг и анализ файла, возвращает список моделей Traffic.
func (s *TrafficService) analyzeFile(filename string) []models.Traffic {
	parser := prs.NewParser()
	packets := parser.Parse(filename)
	flows := divideByFlow(packets)

	// Разбиваем на временные окна для DDoS и Overload детекторов
	windows := pkt.SplitIntoWindows(packets, 10*time.Second)

	// Синхронный анализ окон (DDoS, Overload)
	anomalousFlows := make(map[string]string) // flowID -> detectorName
	for _, det := range s.detectors {
		if dd, ok := det.(interface {
			AnalyzeWindows([]pkt.TimeWindow) []pkt.TimeWindow
		}); ok {
			anomalousWins := dd.AnalyzeWindows(windows)
			for _, win := range anomalousWins {
				for flowID, flow := range flows {
					if len(flow.Packets) == 0 {
						continue
					}
					firstPkt := flow.Packets[0].Timestamp
					if (firstPkt.After(win.StartTime) || firstPkt.Equal(win.StartTime)) &&
						(firstPkt.Before(win.EndTime) || firstPkt.Equal(win.EndTime)) {
						anomalousFlows[flowID] = det.Name()
					}
				}
			}
		}
	}

	var results []models.Traffic

	for _, flow := range flows {
		pkt.AnalyzeFlow(flow)

		trafficModel := MapFlowToTraffic(flow)

		// Per-flow детекторы (Worm, Virus)
		for _, d := range s.detectors {
			detRes := d.Analyze(flow.Stats)
			if detRes.IsAnomaly {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detRes.Type.String(),
				})
			}
		}

		// FlowDetector'ы (P2MP, FlowSwitching и т.д.)
		for _, fd := range s.flowDetectors {
			detRes := fd.AnalyzeFlow(flow)
			if detRes.IsAnomaly {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detRes.Type.String(),
				})
			}
		}

		// DDoS/Overload аномалии из анализа окон
		if detName, ok := anomalousFlows[flow.FlowID]; ok {
			if detName == "DDoSDetector" {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detector.AnomalyDoS.String(),
				})
			} else if detName == "OverloadDetector" {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detector.AnomalyOverload.String(),
				})
			}
		}

		results = append(results, trafficModel)
	}

	return results
}

// buildSummary создаёт JSON-summary для upload'а на основе результатов анализа
func buildSummary(results []models.Traffic, totalPackets int) string {
	flowCount := len(results)

	var bpsSum, avgPktSum, iatSum float64
	for _, t := range results {
		bpsSum += t.BPS
		avgPktSum += t.AvgPacketSize
		iatSum += t.IATms
	}

	var bpsAvg, avgPktAvg, iatAvg float64
	if flowCount > 0 {
		bpsAvg = bpsSum / float64(flowCount)
		avgPktAvg = avgPktSum / float64(flowCount)
		iatAvg = iatSum / float64(flowCount)
	}

	// Подсчитываем угрозы
	knownTypes := []string{
		"DoS/DDoS Attack",
		"Network Overload",
		"Network/Port Scanning",
		"Worm Activity",
		"Confirmed Virus Activity",
		"Point-to-Multipoint",
		"Flow Switching",
	}
	threatMap := make(map[string]int)
	for _, t := range results {
		for _, a := range t.Anomalies {
			if a.AnomalyType != "" && a.AnomalyType != "None" {
				threatMap[a.AnomalyType]++
			}
		}
	}

	threats := make([]ThreatEntry, 0, len(knownTypes))
	for _, name := range knownTypes {
		threats = append(threats, ThreatEntry{Name: name, Value: threatMap[name]})
	}
	// Добавляем неизвестные типы (если есть)
	for k, v := range threatMap {
		found := false
		for _, known := range knownTypes {
			if k == known {
				found = true
				break
			}
		}
		if !found {
			threats = append(threats, ThreatEntry{Name: k, Value: v})
		}
	}

	summary := UploadSummary{
		Packets:          totalPackets,
		Flows:            flowCount,
		BPSAvg:           bpsAvg,
		AvgPacketSizeAvg: avgPktAvg,
		IATmsAvg:         iatAvg,
		ThreatSummary:    threats,
	}

	data, _ := json.Marshal(summary)
	return string(data)
}

// PipelineAsync — асинхронный пайплайн с SSE-прогрессом для фронтенда.
// Создаёт Upload, парсит файл, анализирует, сохраняет в БД.
func (s *TrafficService) PipelineAsync(filename string, uploadID uint) {
	// Phase 1: Parsing
	s.sendProgress(uploadID, "parsing", 10)

	parser := prs.NewParser()
	packets := parser.Parse(filename)

	s.sendProgress(uploadID, "parsing", 40)

	flows := divideByFlow(packets)
	windows := pkt.SplitIntoWindows(packets, 10*time.Second)

	s.sendProgress(uploadID, "analyzing", 50)

	// Phase 2: Analyzing
	anomalousFlows := make(map[string]string)
	for _, det := range s.detectors {
		if dd, ok := det.(interface {
			AnalyzeWindows([]pkt.TimeWindow) []pkt.TimeWindow
		}); ok {
			anomalousWins := dd.AnalyzeWindows(windows)
			for _, win := range anomalousWins {
				for flowID, flow := range flows {
					if len(flow.Packets) == 0 {
						continue
					}
					firstPkt := flow.Packets[0].Timestamp
					if (firstPkt.After(win.StartTime) || firstPkt.Equal(win.StartTime)) &&
						(firstPkt.Before(win.EndTime) || firstPkt.Equal(win.EndTime)) {
						anomalousFlows[flowID] = det.Name()
					}
				}
			}
		}
	}

	s.sendProgress(uploadID, "analyzing", 70)

	var results []models.Traffic
	for _, flow := range flows {
		pkt.AnalyzeFlow(flow)
		trafficModel := MapFlowToTraffic(flow)
		trafficModel.UploadID = &uploadID

		for _, d := range s.detectors {
			detRes := d.Analyze(flow.Stats)
			if detRes.IsAnomaly {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detRes.Type.String(),
				})
			}
		}

		for _, fd := range s.flowDetectors {
			detRes := fd.AnalyzeFlow(flow)
			if detRes.IsAnomaly {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detRes.Type.String(),
				})
			}
		}

		if detName, ok := anomalousFlows[flow.FlowID]; ok {
			if detName == "DDoSDetector" {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detector.AnomalyDoS.String(),
				})
			} else if detName == "OverloadDetector" {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detector.AnomalyOverload.String(),
				})
			}
		}

		results = append(results, trafficModel)
	}

	// Phase 3: Saving
	s.sendProgress(uploadID, "saving", 80)

	var trafficRecords []*models.Traffic
	for i := range results {
		trafficRecords = append(trafficRecords, &results[i])
	}

	err := s.repo.CreateBulk(trafficRecords)
	if err != nil {
		fmt.Printf("Error saving traffic for upload %d: %v\n", uploadID, err)
		s.sendProgress(uploadID, "error", 0)
		return
	}

	// Отправляем записи в broadcast для WebSocket
	for i := range results {
		s.broadcast <- results[i]
	}

	s.sendProgress(uploadID, "saving", 90)

	// Обновляем Upload с summary
	totalPackets := 0
	for _, r := range results {
		totalPackets += r.Packets
	}
	summaryJSON := buildSummary(results, totalPackets)

	upload, err := s.repo.GetUploadByID(uploadID)
	if err == nil {
		upload.FlowCount = len(results)
		upload.Summary = summaryJSON
		s.repo.UpdateUpload(upload)
	}

	s.sendProgress(uploadID, "done", 100)
}

// Pipeline — парсит файл, анализирует, СОХРАНЯЕТ в БД и отправляет в broadcast (для реал-тайм данных)
func (s *TrafficService) Pipeline(filename string) ([]models.Traffic, error) {
	results := s.analyzeFile(filename)

	var trafficRecords []*models.Traffic
	for i := range results {
		s.broadcast <- results[i]
		trafficRecords = append(trafficRecords, &results[i])
	}

	err := s.repo.CreateBulk(trafficRecords)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// PipelineAnalyzeOnly — парсит файл и анализирует, но НЕ сохраняет в БД.
func (s *TrafficService) PipelineAnalyzeOnly(filename string) []models.Traffic {
	return s.analyzeFile(filename)
}
