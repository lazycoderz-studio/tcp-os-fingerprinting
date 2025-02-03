package main

import (
	"github.com/lazycoderz-studio/tcp_fingerprinting/analysis"
	logging "github.com/lazycoderz-studio/tcp_fingerprinting/logger"
	"github.com/lazycoderz-studio/tcp_fingerprinting/packet"
	"github.com/lazycoderz-studio/tcp_fingerprinting/response"
)

func main() {
	capture, err := packet.NewCapture()
	if err != nil {
		panic(err)
	}
	capture.Start()

	for pkt := range capture.PacketChan {
		ip, _ := packet.ParseIPv4(pkt)
		if ip == nil {
			continue
		}
		tcp, _ := packet.ParseTCP(pkt, ip)
		if tcp == nil || (tcp.Flags&0x02) == 0 {
			continue // Not a SYN packet
		}

		signals := analysis.ExtractSignals(ip, tcp)
		os := analysis.Analyze(signals)
		logging.LogDetection(signals, os)

		response.SendRST(ip, tcp)
	}
}
