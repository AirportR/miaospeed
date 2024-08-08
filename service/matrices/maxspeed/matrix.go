package maxspeed

import (
	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/service/macros/speed"
)

type MaxSpeed struct {
	interfaces.MaxSpeedDS
}

func (m *MaxSpeed) Type() interfaces.SlaveRequestMatrixType {
	return interfaces.MatrixMaxSpeed
}

func (m *MaxSpeed) MacroJob() interfaces.SlaveRequestMacroType {
	return interfaces.MacroSpeed
}

func (m *MaxSpeed) Extract(entry interfaces.SlaveRequestMatrixEntry, macro interfaces.SlaveRequestMacro) {
	if mac, ok := macro.(*speed.Speed); ok {
		m.Value = mac.MaxSpeed
	}
}
