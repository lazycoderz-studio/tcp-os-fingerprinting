package response

import (
	"encoding/binary"
	"syscall"

	"github.com/lazycoderz-studio/tcp_fingerprinting/packet"
)

func SendRST(ip *packet.IPv4Header, tcp *packet.TCPHeader) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	ipHeader := createIPHeader(ip)
	tcpHeader := createTCPHeader(tcp)
	packet := append(ipHeader, tcpHeader...)
	dstAddr := syscall.SockaddrInet4{
		Port: int(tcp.SrcPort),
		Addr: [4]byte(ip.SrcIP.To4()),
	}
	return syscall.Sendto(fd, packet, 0, &dstAddr)
}

func createIPHeader(ip *packet.IPv4Header) []byte {
	// Simplified IP header creation
	b := make([]byte, 20)
	b[0] = 0x45 // Version and IHL
	b[8] = 64   // TTL
	b[9] = 6    // Protocol (TCP)
	copy(b[12:16], ip.DstIP.To4())
	copy(b[16:20], ip.SrcIP.To4())
	// Compute checksum here
	return b
}

func createTCPHeader(tcp *packet.TCPHeader) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], tcp.DstPort)
	binary.BigEndian.PutUint16(b[2:4], tcp.SrcPort)
	binary.BigEndian.PutUint16(b[12:14], tcp.Flags|0x04) // Set RST flag
	// Compute checksum here
	return b
}
