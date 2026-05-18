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

	// Синхронный анализ окон (DDoS, Overload)
	anomalousFlows := make(map[string]string) // flowID -> detectorName
	for _, det := range s.detectors {
		if dd, ok := det.(interface {
			AnalyzeWindows([]pkt.TimeWindow) []pkt.TimeWindow
		}); ok {
			anomalousWins := dd.AnalyzeWindows(windows)
			if len(anomalousWins) > 0 {
				for flowID, flow := range flows {
					if len(flow.Packets) == 0 {
						continue
					}
					firstPkt := flow.Packets[0].Timestamp
					for _, win := range anomalousWins {
						if (firstPkt.After(win.StartTime) || firstPkt.Equal(win.StartTime)) &&
							(firstPkt.Before(win.EndTime) || firstPkt.Equal(win.EndTime)) {
							anomalousFlows[flowID] = det.Name()
							break
						}
					}
				}
			}
		}
	}

	var results []models.Traffic

	for _, flow := range flows {
		pkt.AnalyzeFlow(flow)

		trafficModel := MapFlowToTraffic(flow)
		trafficModel.UploadID = uploadID

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
