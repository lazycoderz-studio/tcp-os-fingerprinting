package logging

import (
	"log"

	"github.com/lazycoderz-studio/tcp_fingerprinting/analysis"
)

func LogDetection(signals *analysis.Signals, os string) {
	log.Printf("Detected OS: %s, TTL: %d, Window: %d, MSS: %d, Options: %v",
		os, signals.TTL, signals.Window, signals.MSS, signals.OptionsOrder)
}
