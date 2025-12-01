package matrices

import (
	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/service/macros/hijack"
)

type Hijack struct {
	interfaces.HijackDS
}

func (m *Hijack) Type() interfaces.SlaveRequestMatrixType {
	return interfaces.MatrixHijack
}

func (m *Hijack) MacroJob() interfaces.SlaveRequestMacroType {
	return interfaces.MacroHijack
}

func (m *Hijack) Extract(entry interfaces.SlaveRequestMatrixEntry, macro interfaces.SlaveRequestMacro) {
	if mac, ok := macro.(*hijack.Hijack); ok {
		m.SpeedIP = mac.SpeedIP
		m.RealIP = mac.RealIP
	}
}
