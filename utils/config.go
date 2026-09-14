package utils

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/utils/structs"
)

type GlobalConfig struct {
	Token                 string
	Binder                string
	PprofBinder           string
	NetworkInterface      string
	WhiteList             []string
	AllowIPs              []string
	SpeedLimit            uint64
	TaskLimit             uint
	PauseSecond           uint
	ConnTaskTreading      uint
	MiaoKoSignedTLS       bool
	NoSpeedFlag           bool
	EnableUploadSpeedFlag bool
	EnableIPv6            bool
	MaxmindDB             string
	Path                  string
	ConnectURL            string
	ConnectURLs           []string `json:"ConnectURLs,omitempty"`
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

// SplitConnectValues splits a single -connect flag value into endpoint URLs.
func SplitConnectValues(raw string) []string {
	values := make([]string, 0, 1)
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			values = append(values, part)
		}
	}
	return values
}

// ParseConnectEndpoints validates and normalizes the reverse endpoints given
// through -connect, and returns:
//   - valid: usable endpoints in their original order, with duplicates removed;
//   - rejected: values that are not a usable ws/wss url, fatal for the caller;
//   - duplicated: values dropped because the same endpoint was already given,
//     worth a warning but never a fatal error.
func ParseConnectEndpoints(raw []string) (valid []string, rejected []string, duplicated []string) {
	seen := make(map[string]bool, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}

		target, err := url.Parse(trimmed)
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %s", trimmed, err.Error()))
			continue
		}
		target.Scheme = strings.ToLower(target.Scheme)
		target.Host = strings.ToLower(target.Host)
		if target.Scheme != "ws" && target.Scheme != "wss" {
			rejected = append(rejected, fmt.Sprintf("%s: scheme must be ws or wss", trimmed))
			continue
		}
		if target.Host == "" {
			rejected = append(rejected, fmt.Sprintf("%s: missing host", trimmed))
			continue
		}

		normalized := target.String()
		if seen[normalized] {
			duplicated = append(duplicated, normalized)
			continue
		}
		seen[normalized] = true
		valid = append(valid, normalized)
	}
	return valid, rejected, duplicated
}

// ConnectEndpoints returns the reverse endpoints that should be served: the
// multi endpoint list when it is set, otherwise the legacy single endpoint.
// The fallback is what keeps callers that only assign ConnectURL working.
func (gc *GlobalConfig) ConnectEndpoints() []string {
	if len(gc.ConnectURLs) > 0 {
		return gc.ConnectURLs
	}
	if gc.ConnectURL != "" {
		return []string{gc.ConnectURL}
	}
	return nil
}

var GCFG GlobalConfig
