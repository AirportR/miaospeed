package ping

import (
	"github.com/airportr/miaospeed/interfaces"
)

type Ping struct {
	RTT         uint16
	Request     uint16
	MaxRTT      uint16
	MaxRequest  uint16
	RTTSD       float64
	RequestSD   float64
	RTTList     []uint16
	RequestList []uint16
	StatusCodes []int
	PacketLoss  float64
	Jitter      float64
}

func (m *Ping) Type() interfaces.SlaveRequestMacroType {
	return interfaces.MacroPing
}

func (m *Ping) Run(proxy interfaces.Vendor, r *interfaces.SlaveRequest) error {
	ping(m, proxy, r.Configs.PingAddress, r.Configs.PingAverageOver, r.Configs.TaskTimeout)
	return nil
}
