package script

import (
	"time"

	"github.com/airportr/miaospeed/engine"
	"github.com/airportr/miaospeed/engine/helpers"
	"github.com/airportr/miaospeed/interfaces"
	"github.com/dop251/goja"
)

func ExecScript(p interfaces.Vendor, script *interfaces.Script) interfaces.ScriptResult {
	s := interfaces.ScriptResult{}
	if script == nil {
		return s
	}

	vm := engine.VMNewWithVendor(p, interfaces.ROptionsTCP)

	startTime := time.Now()
	ret, err := engine.RunWithTimeout(vm, time.Duration(script.TimeoutMillis)*time.Millisecond, func() (goja.Value, error) {
		vm.RunString(engine.PREDEFINED_SCRIPT + script.Content)
		return engine.ExecTaskCallback(vm, "handler")
	})

	s.TimeElapsed = time.Now().UnixMilli() - startTime.UnixMilli()
	if engine.ThrowExecTaskErr("MediaTest", err) {
		// nothing here
	} else if text, ok := helpers.VMSafeStr(ret); ok {
		s.Text = text
	} else if ro, _ := helpers.VMSafeObj(vm, ret); ro != nil {
		if v, ok := helpers.VMSafeStr(ro.Get("text")); ok {
			s.Text = v
		}
		if v, ok := helpers.VMSafeStr(ro.Get("color")); ok {
			s.Color = v
		}
		if v, ok := helpers.VMSafeStr(ro.Get("background")); ok {
			s.Background = v
		}
	}

	vm = nil

	return s
}

func FormatExtraMatriceScriptResult(script string, matrix interfaces.SlaveRequestMatrix) interfaces.ScriptResult {
	s := interfaces.ScriptResult{}
	if script == "" || matrix == nil {
		return s
	}

	vm := engine.VMNew()

	vm.RunString(engine.PREDEFINED_SCRIPT + script)
	ret, err := engine.ExecTaskCallback(vm, "matrice_formatter", matrix)
	if err != nil {
		ret, err = engine.ExecTaskCallback(vm, "matrix_extract", matrix)
	}

	if engine.ThrowExecTaskErr("Extra Matrice Format", err) {
		// nothing here
	} else if text, ok := helpers.VMSafeStr(ret); ok {
		s.Text = text
	} else if ro, _ := helpers.VMSafeObj(vm, ret); ro != nil {
		if v, ok := helpers.VMSafeStr(ro.Get("text")); ok {
			s.Text = v
		}
		if v, ok := helpers.VMSafeStr(ro.Get("color")); ok {
			s.Color = v
		}
		if v, ok := helpers.VMSafeStr(ro.Get("background")); ok {
			s.Background = v
		}
	}

	vm = nil

	return s
}
