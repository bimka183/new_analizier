package main

import "analizier/backend/src/models"

type UploadFlowSummary struct {
	Flows            int     `json:"flows"`
	Packets          int     `json:"packets"`
	DurationSecTotal float64 `json:"duration_sec_total"`
	DurationSecAvg   float64 `json:"duration_sec_avg"`
	BPSAvg           float64 `json:"bps_avg"`
	AvgPacketSizeAvg float64 `json:"avg_packet_size_avg"`
	StdDevPacketAvg  float64 `json:"std_dev_packet_size_avg"`
	FlowLengthAvg    float64 `json:"flow_length_avg"`
	IATmsAvg         float64 `json:"iat_ms_avg"`
	TcpSynTotal      int     `json:"cnt_syn_total"`
	TcpAckTotal      int     `json:"cnt_ack_total"`
	TcpFinTotal      int     `json:"cnt_fin_total"`
	TcpPshTotal      int     `json:"cnt_psh_total"`
	TcpRstTotal      int     `json:"cnt_rst_total"`
	TcpUrgTotal      int     `json:"cnt_urg_total"`
}

func enrichTrafficFlowStats(traffic *models.Traffic) {
	if traffic == nil {
		return
	}

	if traffic.Packets <= 0 {
		traffic.Packets = 1
	}

	if traffic.FlowLength <= 0 {
		if traffic.TrafficVolume > 0 {
			traffic.FlowLength = traffic.TrafficVolume
		} else if traffic.Length > 0 {
			traffic.FlowLength = traffic.Length
		}
	}

	if traffic.AvgPacketSize <= 0 && traffic.Packets > 0 && traffic.FlowLength > 0 {
		traffic.AvgPacketSize = float64(traffic.FlowLength) / float64(traffic.Packets)
	}

	if traffic.BPS <= 0 && traffic.FlowLength > 0 {
		if traffic.DurationSec > 0 {
			traffic.BPS = float64(traffic.FlowLength) / traffic.DurationSec
		} else {
			traffic.BPS = float64(traffic.FlowLength)
		}
	}
}

func buildUploadFlowSummary(results []models.Traffic) UploadFlowSummary {
	flows := len(results)
	if flows == 0 {
		return UploadFlowSummary{}
	}

	var packetsTotal int
	var durationTotal float64
	var bpsTotal float64
	var avgPacketSizeTotal float64
	var stdDevPacketSizeTotal float64
	var flowLengthTotal int
	var iatMsTotal float64
	var synTotal, ackTotal, finTotal, pshTotal, rstTotal, urgTotal int

	for _, row := range results {
		packetsTotal += row.Packets
		durationTotal += row.DurationSec
		bpsTotal += row.BPS
		avgPacketSizeTotal += row.AvgPacketSize
		stdDevPacketSizeTotal += row.StdDevPacketSize
		flowLengthTotal += row.FlowLength
		iatMsTotal += row.IATms
		synTotal += row.CntSYN
		ackTotal += row.CntACK
		finTotal += row.CntFIN
		pshTotal += row.CntPSH
		rstTotal += row.CntRST
		urgTotal += row.CntURG
	}

	denom := float64(flows)

	return UploadFlowSummary{
		Flows:            flows,
		Packets:          packetsTotal,
		DurationSecTotal: durationTotal,
		DurationSecAvg:   durationTotal / denom,
		BPSAvg:           bpsTotal / denom,
		AvgPacketSizeAvg: avgPacketSizeTotal / denom,
		StdDevPacketAvg:  stdDevPacketSizeTotal / denom,
		FlowLengthAvg:    float64(flowLengthTotal) / denom,
		IATmsAvg:         iatMsTotal / denom,
		TcpSynTotal:      synTotal,
		TcpAckTotal:      ackTotal,
		TcpFinTotal:      finTotal,
		TcpPshTotal:      pshTotal,
		TcpRstTotal:      rstTotal,
		TcpUrgTotal:      urgTotal,
	}
}
