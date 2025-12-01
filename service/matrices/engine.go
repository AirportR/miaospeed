package matrices

import (
	"github.com/airportr/miaospeed/engine"
	"github.com/airportr/miaospeed/engine/helpers"
	"github.com/airportr/miaospeed/interfaces"
)

type scriptMatrixEntry struct {
	Name   string `json:"name"`
	Params string `json:"params"`
}

func ExecExtraMatriceExtract(script string) (interfaces.SlaveRequestMatrixEntry, bool) {
	vm := engine.VMNew()
	vm.RunString(engine.PREDEFINED_SCRIPT + script)

	scriptEntry := &scriptMatrixEntry{}
	helpers.VMSafeMarshal(scriptEntry, vm.Get("MS_MATRICE_ENTRY"), vm)
	if scriptEntry.Name == "" {
		return interfaces.SlaveRequestMatrixEntry{}, false
	}

	entry := interfaces.SlaveRequestMatrixEntry{
		Type:   interfaces.SlaveRequestMatrixType(scriptEntry.Name),
		Params: scriptEntry.Params,
	}

	return entry, true
}
