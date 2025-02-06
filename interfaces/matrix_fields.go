package interfaces

type InvalidDS struct{}

type HTTPPingDS struct {
	Value uint16
}

type RTTPingDS struct {
	Value uint16
}

type AverageSpeedDS struct {
	Value uint64
}

type MaxSpeedDS struct {
	Value uint64
}

type MaxRTTDS struct {
	Value uint16
}

type HTTPStatusCodeDS struct {
	Values []int
}
type MaxHTTPDS struct {
	Value uint16
}

type SDRTTDS struct {
	Value float64
}
type SDHTTPDS struct {
	Value float64
}
type PacketLossDS struct {
	Value float64
}

type PerSecondSpeedDS struct {
	Max     uint64
	Average uint64
	Speeds  []uint64
}

type TotalRTTDS struct {
	Values []uint16
}

type TotalHTTPDS struct {
	Values []uint16
}

type UDPTypeDS struct {
	Value string
}

type ScriptTestDS struct {
	Key string
	ScriptResult
}

type InboundGeoIPDS struct {
	MultiStacks
}

type OutboundGeoIPDS struct {
	MultiStacks
}
