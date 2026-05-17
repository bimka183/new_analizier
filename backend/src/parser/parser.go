package parser

import (
	"fmt"
	"io"
	"net"

	pkt "analizier/backend/src/packet"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func getInterfaceName(index int) string {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return fmt.Sprintf("unknown (index: %d)", index)
	}
	return iface.Name
}

type Parser struct {
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) getInfo(packet gopacket.Packet) []string {
	transLayer := packet.TransportLayer()
	var flags []string
	if tcpLayer, ok := transLayer.(*layers.TCP); ok {
		if tcpLayer.SYN {
			flags = append(flags, "SYN")
		}
		if tcpLayer.ACK {
			flags = append(flags, "ACK")
		}
		if tcpLayer.FIN {
			flags = append(flags, "FIN")
		}
		if tcpLayer.RST {
			flags = append(flags, "RST")
		}
		if tcpLayer.PSH {
			flags = append(flags, "PSH")
		}
		if tcpLayer.URG {
			flags = append(flags, "URG")
		}
	}
	return flags
}

// getProtocol определяет тип протокола транспортного уровня
func (p *Parser) getProtocol(packet gopacket.Packet) string {
	transLayer := packet.TransportLayer()
	if transLayer == nil {
		// Проверяем ICMP на сетевом уровне
		if packet.Layer(layers.LayerTypeICMPv4) != nil {
			return "ICMP"
		}
		if packet.Layer(layers.LayerTypeICMPv6) != nil {
			return "ICMPv6"
		}
		return "Other"
	}
	switch transLayer.LayerType() {
	case layers.LayerTypeTCP:
		return "TCP"
	case layers.LayerTypeUDP:
		return "UDP"
	default:
		return transLayer.LayerType().String()
	}
}

func (p *Parser) Parse(filename string) ([]pkt.PacketInfo, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file: %w", err)
	}
	defer handle.Close()

	linkType := handle.LinkType()
	packetSource := gopacket.NewPacketSource(handle, linkType)
	packetNum := 0

	result := make([]pkt.PacketInfo, 0)

	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			// Skip corrupted or unreadable packets to continue parsing the rest of the file
			continue
		}
		packetNum++
		info := pkt.PacketInfo{
			PacketNumber:  packetNum,
			Interface:     getInterfaceName(packet.Metadata().InterfaceIndex),
			Timestamp:     packet.Metadata().Timestamp,
			Length:        int(packet.Metadata().Length),
			TrafficVolume: int(packet.Metadata().CaptureInfo.Length),
			Protocol:      p.getProtocol(packet),
		}

		if netLayer := packet.NetworkLayer(); netLayer != nil {
			flow := netLayer.NetworkFlow()
			info.FlowID = flow
			src, dst := flow.Endpoints()
			info.SrcIP = src.String()
			info.DstIP = dst.String()

			netLayerType := netLayer.LayerType()
			if netLayerType == layers.LayerTypeIPv4 {
				info.IPVersion = "IPv4"
			} else if netLayerType == layers.LayerTypeIPv6 {
				info.IPVersion = "IPv6"
			}
		} else if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			if arp != nil {
				info.SrcIP = net.IP(arp.SourceProtAddress).String()
				info.DstIP = net.IP(arp.DstProtAddress).String()
				info.IPVersion = "ARP"
			}
		}

		// Fallback to LinkLayer MAC addresses if we don't have IP/ARP addresses
		if info.SrcIP == "" || info.DstIP == "" {
			if linkLayer := packet.LinkLayer(); linkLayer != nil {
				flow := linkLayer.LinkFlow()
				src, dst := flow.Endpoints()
				info.SrcIP = src.String()
				info.DstIP = dst.String()
				info.IPVersion = "Ethernet"
			}
		}

		if transLayer := packet.TransportLayer(); transLayer != nil {
			flow := transLayer.TransportFlow()
			info.FlowID = flow
			src, dst := flow.Endpoints()
			info.SrcPort = src.String()
			info.DstPort = dst.String()
		}

		// Normalize empty Ports to "0" to keep flow grouping consistent
		if info.SrcPort == "" {
			info.SrcPort = "0"
		}
		if info.DstPort == "" {
			info.DstPort = "0"
		}

		info.Flags = p.getInfo(packet)
		result = append(result, info)
	}

	return result, nil
}
