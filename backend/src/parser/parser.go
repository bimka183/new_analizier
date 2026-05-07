package parser

import (
	"fmt"
	"log"
	"net"
	"strings"

	pkt "analizier/backend/src/packet"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	utls "github.com/refraction-networking/utls"
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

func (p *Parser) generateJA3String(ch *utls.PubClientHelloMsg) string {
	version := fmt.Sprintf("%d", ch.Vers)

	ciphers := make([]string, 0, len(ch.CipherSuites))
	for _, cs := range ch.CipherSuites {
		ciphers = append(ciphers, fmt.Sprintf("%d", cs))
	}
	ciphersStr := strings.Join(ciphers, "-")

	extensions := p.getExtensionsList(ch)
	extensionsStr := strings.Join(extensions, "-")

	curves := make([]string, 0, len(ch.SupportedCurves))
	for _, curve := range ch.SupportedCurves {
		curves = append(curves, fmt.Sprintf("%d", curve))
	}
	curvesStr := strings.Join(curves, "-")

	pointFormats := make([]string, 0, len(ch.SupportedPoints))
	for _, pf := range ch.SupportedPoints {
		pointFormats = append(pointFormats, fmt.Sprintf("%d", pf))
	}
	pointFormatsStr := strings.Join(pointFormats, "-")

	ja3 := fmt.Sprintf("%s,%s,%s,%s,%s", version, ciphersStr, extensionsStr, curvesStr, pointFormatsStr)
	return ja3
}

func (p *Parser) getExtensionsList(ch *utls.PubClientHelloMsg) []string {
	var extensions []string

	if ch.ServerName != "" {
		extensions = append(extensions, "0")
	}
	if ch.NextProtoNeg {
		extensions = append(extensions, "13172")
	}
	if ch.OcspStapling {
		extensions = append(extensions, "5")
	}
	if ch.Scts {
		extensions = append(extensions, "18")
	}
	if ch.TicketSupported {
		extensions = append(extensions, "9")
	}
	if len(ch.AlpnProtocols) > 0 {
		extensions = append(extensions, "16")
	}
	if len(ch.SupportedCurves) > 0 {
		extensions = append(extensions, "10")
	}
	if len(ch.SupportedPoints) > 0 {
		extensions = append(extensions, "11")
	}
	if len(ch.SupportedSignatureAlgorithms) > 0 {
		extensions = append(extensions, "13")
	}
	if len(ch.SupportedVersions) > 0 {
		extensions = append(extensions, "43")
	}
	if ch.Ems {
		extensions = append(extensions, "23")
	}

	return extensions
}

func (p *Parser) extractTLS(payload []byte) *pkt.TLSInfo {
	if len(payload) < 6 || payload[0] != 0x16 || payload[5] != 0x01 {
		return nil
	}
	ch := utls.UnmarshalClientHello(payload)
	if ch == nil {
		return nil
	}
	return &pkt.TLSInfo{
		JA3: p.generateJA3String(ch),
		SNI: ch.ServerName,
	}
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

func (p *Parser) Parse(filename string) []pkt.PacketInfo {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	linkType := handle.LinkType()
	packetSource := gopacket.NewPacketSource(handle, linkType)
	packetNum := 0

	result := make([]pkt.PacketInfo, 0)
	flows := make(map[string]*pkt.FlowInfo)

	for packet := range packetSource.Packets() {
		packetNum++

		var payload []byte
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload = appLayer.Payload()
		}

		info := pkt.PacketInfo{
			PacketNumber:  packetNum,
			Interface:     getInterfaceName(packet.Metadata().InterfaceIndex),
			Timestamp:     packet.Metadata().Timestamp,
			Length:        int(packet.Metadata().Length),
			TrafficVolume: int(packet.Metadata().CaptureInfo.Length),
			Payload:       payload,
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
		}
		if transLayer := packet.TransportLayer(); transLayer != nil {
			flow := transLayer.TransportFlow()
			info.FlowID = flow
			src, dst := flow.Endpoints()
			info.SrcPort = src.String()
			info.DstPort = dst.String()
		}
		info.Flags = p.getInfo(packet)

		flowID := info.FlowID.String()
		flow, exists := flows[flowID]
		if !exists {
			flow = &pkt.FlowInfo{
				FlowID:        flowID,
				Interface:     info.Interface,
				SourceIP:      info.SrcIP,
				DestinationIP: info.DstIP,
				IPVersion:     info.IPVersion,
				SourcePort:    info.SrcPort,
				DestPort:      info.DstPort,
				Packets:       []pkt.PacketInfo{},
				Stats:         pkt.FlowStats{},
			}
			flows[flowID] = flow
		}

		flow.Packets = append(flow.Packets, info)
		pkt.AnalyzeFlow(flow)

		if info.DstPort == "443" && len(payload) > 0 && flow.Stats.TLS == nil {
			tlsInfo := p.extractTLS(payload)
			if tlsInfo != nil {
				flow.Stats.TLS = tlsInfo
				pkt.AnalyzeFlow(flow)
			}
		}

		result = append(result, info)
	}

	return result
}
