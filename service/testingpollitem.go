package service

import (
	"sync"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/service/macros"
	"github.com/airportr/miaospeed/service/macros/invalid"
	mscript "github.com/airportr/miaospeed/service/macros/script"
	"github.com/airportr/miaospeed/service/matrices"
	"github.com/airportr/miaospeed/service/taskpoll"
	"github.com/airportr/miaospeed/utils"
	"github.com/airportr/miaospeed/utils/structs"
	"github.com/airportr/miaospeed/vendors"
)

type TestingPollItem struct {
	id   string
	name string

	request       *interfaces.SlaveRequest
	matrices      []interfaces.SlaveRequestMatrixEntry
	matricesExtra map[string]interfaces.SlaveRequestMatrixEntry
	macros        []interfaces.SlaveRequestMacroType
	results       *structs.AsyncArr[interfaces.SlaveEntrySlot]

	onProcess  func(self *TestingPollItem, idx int, result interfaces.SlaveEntrySlot)
	onExit     func(self *TestingPollItem, exitCode taskpoll.TPExitCode)
	calcWeight func(self *TestingPollItem) uint

	onProcessLock sync.Mutex
	exitOnce      sync.Once
}

func (tpi *TestingPollItem) ID() string {
	return tpi.id
}

func (tpi *TestingPollItem) TaskName() string {
	return tpi.name
}

func (tpi *TestingPollItem) Weight() uint {
	// TODO: could arrange weight based on task size
	// or customized rules
	if tpi.calcWeight != nil {
		return tpi.calcWeight(tpi)
	}
	return 1
}

func (tpi *TestingPollItem) Count() int {
	return len(tpi.request.Nodes)
}

func (tpi *TestingPollItem) Yield(idx int, tpc *taskpoll.TPController) {
	result := interfaces.SlaveEntrySlot{
		ProxyInfo:      interfaces.ProxyInfo{},
		InvokeDuration: -1,
		Matrices:       []interfaces.MatrixResponse{},
	}

	defer func() {
		utils.WrapErrorPure("Task yield error", recover())
		tpi.results.Push(result)
		tpi.onProcessLock.Lock()
		defer tpi.onProcessLock.Unlock()
		// utils.DWarnf("Task yield idx %d, tpc: %s", idx, tpc.Name())
		tpi.onProcess(tpi, idx, result)
	}()

	if tpi.request == nil || idx < 0 || idx >= len(tpi.request.Nodes) {
		pollName := "unknown"
		if tpc != nil {
			pollName = tpc.Name()
		}
		nodeCount := 0
		if tpi.request != nil {
			nodeCount = len(tpi.request.Nodes)
		}
		utils.DWarnf("Task yield skipped due to invalid index, poll=%s task=%s idx=%d nodes=%d", pollName, tpi.TaskName(), idx, nodeCount)
		return
	}

	node := tpi.request.Nodes[idx]
	vendor := vendors.Find(tpi.request.Vendor).Build(node.Name, node.Payload)
	if dnsSetter, ok := vendor.(interface{ SetDNSServers([]string) }); ok {
		dnsSetter.SetDNSServers(tpi.request.Configs.DNSServers)
	}
	result.ProxyInfo = vendor.ProxyInfo()
	macroMap := structs.NewAsyncMap[interfaces.SlaveRequestMacroType, interfaces.SlaveRequestMacro]()

	startTime := time.Now().UnixMilli()

	// When the number of speedtest threads is large (download or upload > 8),
	// the speedtest saturates the bandwidth for a long time, inflating latency
	// measurements when running concurrently with Ping (bufferbloat). With
	// threads <= 8 the interference is limited, so keep the original concurrent
	// behavior. Only when needed, run Ping first on its own (millisecond cost),
	// then run the remaining macros (including speedtest) concurrently.
	preMacros := make([]interfaces.SlaveRequestMacroType, 0, len(tpi.macros))
	postMacros := make([]interfaces.SlaveRequestMacroType, 0, len(tpi.macros))
	if tpi.request.Configs.DownloadThreading > 8 || tpi.request.Configs.UploadThreading > 8 {
		for _, macro := range tpi.macros {
			if macro == interfaces.MacroPing {
				preMacros = append(preMacros, macro)
			} else {
				postMacros = append(postMacros, macro)
			}
		}
	} else {
		postMacros = append(postMacros, tpi.macros...)
	}
	runMacros := func(list []interfaces.SlaveRequestMacroType) {
		wg := sync.WaitGroup{}
		wg.Add(len(list))
		for _, macro := range list {
			macroName := macro
			go func() {
				macro := macros.Find(macroName)
				macro.Run(vendor, tpi.request)
				macroMap.Set(macroName, macro)
				wg.Done()
			}()
		}
		wg.Wait()
	}
	runMacros(preMacros)
	runMacros(postMacros)
	endTime := time.Now().UnixMilli()
	result.InvokeDuration = endTime - startTime

	result.Matrices = structs.Map(tpi.matrices, func(me interfaces.SlaveRequestMatrixEntry) interfaces.MatrixResponse {
		m := matrices.Find(me.Type)
		if m.Type() == interfaces.MatrixScriptTest {
			if entry, ok := tpi.matricesExtra[me.Params]; ok {
				m := matrices.Find(entry.Type)
				macro := macroMap.MustGet(m.MacroJob())
				if macro == nil {
					macro = &invalid.Invalid{}
				}
				m.Extract(entry, macro)

				scriptResult := interfaces.ScriptResult{}
				if s := structs.Find(tpi.request.Configs.Scripts, func(s interfaces.Script) bool { return s.ID == me.Params }); s != nil {
					scriptResult = mscript.FormatExtraMatriceScriptResult(s.Content, m)
				}

				return interfaces.MatrixResponse{
					Type:    interfaces.MatrixScriptTest,
					Payload: utils.ToJSON(&interfaces.ScriptTestDS{Key: me.Params, ScriptResult: scriptResult}),
				}
			}
		}
		macro := macroMap.MustGet(m.MacroJob())
		if macro == nil {
			macro = &invalid.Invalid{}
		}
		m.Extract(me, macro)

		return interfaces.MatrixResponse{
			Type:    m.Type(),
			Payload: utils.ToJSON(m),
		}
	})
}

func (tpi *TestingPollItem) OnExit(exitCode taskpoll.TPExitCode) {
	tpi.exitOnce.Do(func() {
		tpi.onExit(tpi, exitCode)
	})
}

func (tpi *TestingPollItem) Init() taskpoll.TaskPollItem {
	tpi.results = structs.NewAsyncArr[interfaces.SlaveEntrySlot]()
	return tpi
}
