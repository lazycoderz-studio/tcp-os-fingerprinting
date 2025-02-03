package analysis

var OSProfiles = []OSProfile{
	{
		Name:          "Linux",
		TTL:           64,
		Window:        5840,                 // Typical Linux default window size
		MSS:           1460,                 // Common MSS for Ethernet
		WindowScaling: 7,                    // Window scaling factor
		SACKPermitted: true,                 // SACK allowed
		Timestamp:     true,                 // Timestamps enabled
		OptionsOrder:  []int{2, 4, 8, 3, 1}, // MSS,SACK,TS,WS,EOOL
		DF:            true,                 // Don't Fragment bit set
		Flags:         0x02,                 // SYN flag
	},
	{
		Name:          "Android (Linux)",
		TTL:           64,
		Window:        64240, // Android-specific window size
		MSS:           1430,  // Often lower MSS
		WindowScaling: 6,
		SACKPermitted: true,
		Timestamp:     true,
		OptionsOrder:  []int{1, 3, 0, 4, 2}, // Different option order
		DF:            true,
		Flags:         0x02,
	},
	{
		Name:          "Windows",
		TTL:           128,  // Windows default TTL
		Window:        8192, // Base window size
		MSS:           1460,
		WindowScaling: 8,
		SACKPermitted: true,
		Timestamp:     true,
		OptionsOrder:  []int{3, 1, 8, 4, 2}, // WS,NOP,TS,SACK,MSS
		DF:            true,
		Flags:         0x02,
	},
	{
		Name:          "macOS",
		TTL:           64,
		Window:        65535, // Large window size
		MSS:           1460,
		WindowScaling: 6,
		SACKPermitted: true,
		Timestamp:     true,
		OptionsOrder:  []int{4, 2, 8, 3, 1}, // SACK,MSS,TS,WS,EOOL
		DF:            true,
		Flags:         0x02,
	},
	{
		Name:          "iOS (iPhone)",
		TTL:           64,
		Window:        65535,
		MSS:           1460,
		WindowScaling: 6,
		SACKPermitted: true,
		Timestamp:     true,
		OptionsOrder:  []int{4, 1, 8, 3, 2}, // SACK,NOP,TS,WS,MSS
		DF:            true,
		Flags:         0x02,
	},
}

// TCP Option Kind constants
const (
	TCPOptionKindEOOL      = 0 // End of Option List
	TCPOptionKindNOP       = 1 // No-Operation
	TCPOptionKindMSS       = 2 // Maximum Segment Size
	TCPOptionKindWS        = 3 // Window Scaling
	TCPOptionKindSACK      = 4 // SACK Permitted
	TCPOptionKindTimestamp = 8 // Timestamps
)

// NormalizeTTL accounts for common TTL values
func NormalizeTTL(ttl uint8) uint8 {
	switch {
	case ttl > 128:
		return 128
	case ttl > 64:
		return 64
	case ttl > 32:
		return 32
	default:
		return ttl
	}
}
