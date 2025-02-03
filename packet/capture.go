package packet

import (
	"log"
	"syscall"
)

type Capture struct {
	IPv4FD     int
	IPv6FD     int
	PacketChan chan []byte
}

func NewCapture() (*Capture, error) {
	ipv4FD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	syscall.SetsockoptInt(ipv4FD, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)

	// Note: IPv6 raw socket setup omitted for brevity

	return &Capture{
		IPv4FD:     ipv4FD,
		PacketChan: make(chan []byte, 1000),
	}, nil
}

func (c *Capture) Start() {
	go c.readIPv4()
}

func (c *Capture) readIPv4() {
	buf := make([]byte, 65535)
	for {
		n, _, err := syscall.Recvfrom(c.IPv4FD, buf, 0)
		if err != nil {
			log.Printf("Recvfrom error: %v", err)
			continue
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		c.PacketChan <- packet
	}
}
