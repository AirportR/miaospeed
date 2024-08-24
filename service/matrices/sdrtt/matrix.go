package sdrtt

import (
	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/service/macros/ping"
)

type SDRTT struct {
	interfaces.SDRTTDS
}

func (m *SDRTT) Type() interfaces.SlaveRequestMatrixType {
	return interfaces.MatrixSDRTT
}

func (m *SDRTT) MacroJob() interfaces.SlaveRequestMacroType {
	return interfaces.MacroPing
}

func (m *SDRTT) Extract(entry interfaces.SlaveRequestMatrixEntry, macro interfaces.SlaveRequestMacro) {
	if mac, ok := macro.(*ping.Ping); ok {
		m.Value = mac.RTTSD
	}
}
