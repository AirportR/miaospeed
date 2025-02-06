package utils

import (
	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/utils/structs"
)

type GlobalConfig struct {
	Token            string
	Binder           string
	WhiteList        []string
	AllowIPs         []string
	SpeedLimit       uint64
	TaskLimit        uint
	PauseSecond      uint
	ConnTaskTreading uint
	MiaoKoSignedTLS  bool
	NoSpeedFlag      bool
	EnableIPv6       bool
	MaxmindDB        string
	Path             string
}

func (gc *GlobalConfig) InWhiteList(invoker string) bool {
	if len(gc.WhiteList) == 0 {
		return true
	}

	return structs.Contains(gc.WhiteList, invoker)
}

func (gc *GlobalConfig) VerifyRequest(req *interfaces.SlaveRequest) bool {
	return req.Challenge == gc.SignRequest(req)
}

func (gc *GlobalConfig) SignRequest(req *interfaces.SlaveRequest) string {
	return SignRequest(gc.Token, req)
}

func (gc *GlobalConfig) ValidateWSPath(path string) bool {
	DBlackholef("Path to the websocket to be validated: %s, Predefined websocket path: %s\n", path, gc.Path)
	return path == gc.Path
}

var GCFG GlobalConfig
