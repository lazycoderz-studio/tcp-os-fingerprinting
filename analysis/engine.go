package analysis

import (
	"encoding/binary"

	"github.com/lazycoderz-studio/tcp_fingerprinting/packet"
)

type Signals struct {
	TTL           uint8
	Window        uint16
	MSS           uint16
	WindowScaling uint8
	SACKPermitted bool
	Timestamp     bool
	OptionsOrder  []int
	DF            bool
	Flags         uint16
}

type OSProfile struct {
	Name          string
	TTL           uint8
	Window        uint16
	MSS           uint16
	WindowScaling uint8
	SACKPermitted bool
	Timestamp     bool
	OptionsOrder  []int
	DF            bool
	Flags         uint16
}

func ExtractSignals(ip *packet.IPv4Header, tcp *packet.TCPHeader) *Signals {
	s := &Signals{
		TTL:    ip.TTL,
		DF:     ip.DF,
		Window: tcp.Window,
		Flags:  tcp.Flags,
	}
	var order []int
	for _, opt := range tcp.Options {
		switch opt.Kind {
		case 2:
			if len(opt.Data) >= 2 {
				s.MSS = binary.BigEndian.Uint16(opt.Data)
			}
		case 3:
			if len(opt.Data) >= 1 {
				s.WindowScaling = opt.Data[0]
			}
		case 4:
			s.SACKPermitted = true
		case 8:
			s.Timestamp = true
		}
		order = append(order, int(opt.Kind))
	}
	s.OptionsOrder = order
	return s
}

var osDB = []OSProfile{
	{
		Name:          "Linux",
		TTL:           64,
		Window:        5840,
		MSS:           1460,
		WindowScaling: 7,
		SACKPermitted: true,
		Timestamp:     true,
		OptionsOrder:  []int{2, 4, 8, 3},
		DF:            true,
		Flags:         0x02,
	},
	// Add other OS profiles
}

// Updated Analyze function using OSProfiles
func Analyze(s *Signals) string {
	s.TTL = NormalizeTTL(s.TTL) // Normalize TTL first

	maxScore := 0
	result := "Unknown"

	for _, os := range OSProfiles {
		score := 0

		// TTL matching (5 points)
		if s.TTL == os.TTL {
			score += 5
		}

		// Window size matching (10 points)
		if s.Window == os.Window {
			score += 10
		}

		// Options order matching (20 points)
		if len(s.OptionsOrder) > 0 && sliceEqual(s.OptionsOrder, os.OptionsOrder) {
			score += 20
		}

		// DF bit matching (5 points)
		if s.DF == os.DF {
			score += 5
		}

		// MSS matching (10 points)
		if s.MSS == os.MSS {
			score += 10
		}

		// Flags matching (5 points)
		if s.Flags == os.Flags {
			score += 5
		}

		if score > maxScore {
			maxScore = score
			result = os.Name
		}
	}

	return result
}
func sliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
