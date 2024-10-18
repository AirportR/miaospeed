package debug

import (
	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/service/macros/sleep"
)

type SleepDS struct {
	Value string
}

func (s *SleepDS) Type() interfaces.SlaveRequestMatrixType {
	return interfaces.MatrixSleep
}

func (s *SleepDS) MacroJob() interfaces.SlaveRequestMacroType {
	return interfaces.MacroSleep
}

func (s *SleepDS) Extract(entry interfaces.SlaveRequestMatrixEntry, macro interfaces.SlaveRequestMacro) {
	if mac, ok := macro.(*sleep.Sleep); ok {
		s.Value = mac.Value
	}
}
