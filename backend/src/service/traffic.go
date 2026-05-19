package service

import (
	"analizier/backend/src/detector"
	"analizier/backend/src/models"
	"strings"
	"time"

	pkt "analizier/backend/src/packet"
	prs "analizier/backend/src/parser"
	"analizier/backend/src/repository"
)

func MapFlowToTraffic(flow *pkt.FlowInfo) models.Traffic {
	return models.Traffic{
		FlowID:          flow.FlowID,
		Interface:       flow.Interface,
		Timestamp:       flow.StartTime.Format("2006-01-02 15:04:05"),
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

// flowInvolvesIP — поток связан с IP (любое направление пакетов).
func flowInvolvesIP(flow *pkt.FlowInfo, ip string) bool {
	if ip == "" || flow == nil {
		return false
	}
	if flow.SourceIP == ip || flow.DestinationIP == ip {
		return true
	}
	if flow.Stats.SrcIP == ip || flow.Stats.DstIP == ip {
		return true
	}
	for _, p := range flow.Packets {
		if p.SrcIP == ip || p.DstIP == ip {
			return true
		}
	}
	return false
}

// captureDurationFromPackets — длительность захвата для AggregateBySource (первый–последний пакет).
func captureDurationFromPackets(packets []pkt.PacketInfo) time.Duration {
	if len(packets) < 2 {
		return 0
	}
	d := packets[len(packets)-1].Timestamp.Sub(packets[0].Timestamp)
	if d <= 0 {
		return 0
	}
	return d
}

// flowIntersectsTimeWindow — согласовано с detector.flowIntersectsWindow: любой пакет в [Start, End).
func flowIntersectsTimeWindow(f *pkt.FlowInfo, w pkt.TimeWindow) bool {
	for _, p := range f.Packets {
		t := p.Timestamp
		if !t.Before(w.StartTime) && t.Before(w.EndTime) {
			return true
		}
	}
	return false
}

// runWindowDetectors вызывает DDoS с потоками и остальные оконные детекторы без смены их API.
func (s *TrafficService) runWindowDetectors(windows []pkt.TimeWindow, flows map[string]*pkt.FlowInfo, capDur time.Duration) map[string]string {
	anomalousFlows := make(map[string]string)
	for _, det := range s.detectors {
		var anomalousWins []pkt.TimeWindow
		switch t := det.(type) {
		case *detector.DDoSDetector:
			anomalousWins = t.AnalyzeWindowsWithFlows(windows, flows, capDur)
		default:
			if w, ok := det.(interface {
				AnalyzeWindows([]pkt.TimeWindow) []pkt.TimeWindow
			}); ok {
				anomalousWins = w.AnalyzeWindows(windows)
			}
		}
		for _, win := range anomalousWins {
			for flowID, flow := range flows {
				if len(flow.Packets) == 0 {
					continue
				}
				if flowIntersectsTimeWindow(flow, win) {
					anomalousFlows[flowID] = det.Name()
				}
			}
		}
	}
	return anomalousFlows
}

type TrafficService struct {
	detectors     []detector.Detector
	flowDetectors []detector.FlowDetector
	repo          repository.TrafficRepository
	broadcast     chan models.Traffic
}

func NewTrafficService(
	repo repository.TrafficRepository,
	detectors []detector.Detector,
	flowDetectors []detector.FlowDetector,
	broadcast chan models.Traffic,
) *TrafficService {
	return &TrafficService{
		repo:          repo,
		detectors:     detectors,
		flowDetectors: flowDetectors,
		broadcast:     broadcast,
	}
}

// analyzeFile выполняет парсинг и анализ файла, возвращает список моделей Traffic.
// Общий код для Pipeline и PipelineAnalyzeOnly.
func (s *TrafficService) analyzeFile(filename string, uploadID uint) ([]models.Traffic, error) {
	parser := prs.NewParser()
	packets, err := parser.Parse(filename)
	if err != nil {
		return nil, err
	}
	flows := divideByFlow(packets)

	// Разбиваем на временные окна для DDoS и Overload детекторов
	windows := pkt.SplitIntoWindows(packets, 10*time.Second)

	capDur := captureDurationFromPackets(packets)

	// Синхронный анализ окон: DDoS — AnalyzeWindowsWithFlows (агрегация по источнику);
	// остальные — AnalyzeWindows; привязка потоков по пересечению времени окна с пакетами потока.
	anomalousFlows := s.runWindowDetectors(windows, flows, capDur)

	portScanDet := detector.NewPortScanDetector()
	scanningIPs := portScanDet.ScanningSources(flows, capDur)

	var results []models.Traffic

	for _, flow := range flows {

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

		for scanIP := range scanningIPs {
			if flowInvolvesIP(flow, scanIP) {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detector.AnomalyScanning.String(),
				})
				break
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

	return results, nil
}

// Pipeline — парсит файл, анализирует, СОХРАНЯЕТ в БД и отправляет в broadcast (для реал-тайм данных)
// приходит файл
// парсим файл на PacketInfo
// Разделяем PacketInfo на FlowInfo
// Тут можно записать FlowInfo в БД
// Собираем FlowStats по FlowInfo
// Пропускаем FlowStats через детекторы и получаем DetectionResult
// Если DetectionResult.IsAnomaly добавляем DetectionResult.Type.String() в список аномалий
// Записываем аномалии для каждого FlowInfo в таблицу единым запросом
func (s *TrafficService) Pipeline(filename string, uploadID uint) ([]models.Traffic, error) {
	results, err := s.analyzeFile(filename, uploadID)
	if err != nil {
		return nil, err
	}

	var trafficRecords []*models.Traffic
	for i := range results {
		trafficRecords = append(trafficRecords, &results[i])
	}

	err = s.repo.CreateBulk(trafficRecords)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// PipelineAnalyzeOnly — парсит файл и анализирует, но НЕ сохраняет в БД.
// Используется для загрузки файлов: результат возвращается клиенту напрямую,
// без влияния на основную базу данных.
func (s *TrafficService) PipelineAnalyzeOnly(filename string, uploadID uint) ([]models.Traffic, error) {
	return s.analyzeFile(filename, uploadID)
}
