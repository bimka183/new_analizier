package packet

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"strings"
	"time"
)

type PacketInfo struct {
	PacketNumber  int // № пакета
	FlowID        gopacket.Flow
	Interface     string    // Интерфейс
	Timestamp     time.Time // Текущее время и дата пакета
	TrafficVolume int       // Объем трафика
	SrcIP         string    // Источник (IP адрес)
	DstIP         string    // Назначение (IP адрес)
	IPVersion     string    // Internet Протокол version
	Protocol      string    // Протокол транспортного уровня (TCP, UDP, ICMP и т.д.)
	SrcPort       string    // Порт источника
	DstPort       string    // Порт назначения
	Length        int       // Длина
	Flags         []string
}

func PrintPacketInfo(info PacketInfo) {
	const fieldWidth = 20

	formatField := func(name string, value interface{}) {
		fmt.Printf("%-*s %v\n", fieldWidth, name+":", value)
	}

	fmt.Printf("=== Пакет #%d ===\n", info.PacketNumber)

	formatField("Интерфейс", info.Interface)
	formatField("Время", info.Timestamp.Format("2006-01-02 15:04:05.000000"))
	formatField("Объем трафика", fmt.Sprintf("%d байт", info.TrafficVolume))
	formatField("Источник", info.SrcIP)
	formatField("Назначение", info.DstIP)
	formatField("Версия IP", info.IPVersion)
	formatField("Протокол", info.Protocol)

	if info.SrcPort != "" || info.DstPort != "" {
		formatField("Порт источника", ifEmpty(info.SrcPort, "N/A"))
		formatField("Порт назначения", ifEmpty(info.DstPort, "N/A"))
	}

	formatField("Длина пакета", fmt.Sprintf("%d байт", info.Length))

	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()
}

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
