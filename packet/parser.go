package packet

import (
	"encoding/binary"
	"net"
)

type IPv4Header struct {
	TTL   uint8
	SrcIP net.IP
	DstIP net.IP
	DF    bool
	IHL   int
}

type TCPHeader struct {
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint16
	Window  uint16
	Options []TCPOption
}

type TCPOption struct {
	Kind uint8
	Data []byte
}

func ParseIPv4(packet []byte) (*IPv4Header, error) {
	if len(packet) < 20 {
		return nil, nil
	}
	ihl := int(packet[0]&0x0F) * 4
	ttl := packet[8]
	flags := packet[6] >> 5
	df := (flags & 0x02) != 0
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	return &IPv4Header{
		TTL:   ttl,
		SrcIP: srcIP,
		DstIP: dstIP,
		DF:    df,
		IHL:   ihl,
	}, nil
}

func ParseTCP(packet []byte, ipHeader *IPv4Header) (*TCPHeader, error) {
	tcpStart := ipHeader.IHL
	if len(packet) < tcpStart+20 {
		return nil, nil
	}
	dataOffset := (packet[tcpStart+12] >> 4) * 4
	srcPort := binary.BigEndian.Uint16(packet[tcpStart : tcpStart+2])
	dstPort := binary.BigEndian.Uint16(packet[tcpStart+2 : tcpStart+4])
	flags := binary.BigEndian.Uint16(packet[tcpStart+12 : tcpStart+14])
	window := binary.BigEndian.Uint16(packet[tcpStart+14 : tcpStart+16])
	options := parseTCPOptions(packet[tcpStart+20 : tcpStart+int(dataOffset)])

	return &TCPHeader{
		SrcPort: srcPort,
		DstPort: dstPort,
		Flags:   flags,
		Window:  window,
		Options: options,
	}, nil
}

func parseTCPOptions(data []byte) []TCPOption {
	var options []TCPOption
	for i := 0; i < len(data); {
		if data[i] == 0 {
			break
		}
		if data[i] == 1 {
			options = append(options, TCPOption{Kind: 1})
			i++
			continue
		}
		if i+1 >= len(data) {
			break
		}
		length := int(data[i+1])
		if length < 2 || i+length > len(data) {
			break
		}
		options = append(options, TCPOption{
			Kind: data[i],
			Data: data[i+2 : i+length],
		})
		i += length
	}
	return options
}
