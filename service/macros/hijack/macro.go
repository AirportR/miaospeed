package hijack

import "github.com/airportr/miaospeed/interfaces"

type Hijack struct {
	SpeedIP string
	RealIP  string
}

func (m *Hijack) Type() interfaces.SlaveRequestMacroType {
	return interfaces.MacroHijack
}

func (m *Hijack) Run(proxy interfaces.Vendor, r *interfaces.SlaveRequest) error {
	speedIP, realIP := checkHijack(proxy, interfaces.ROptionsTCP)
	m.SpeedIP = speedIP
	m.RealIP = realIP
	return nil
}
