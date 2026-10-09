package interfaces

import (
	"strings"
)

type ProxyType string

const (
	Shadowsocks  ProxyType = "Shadowsocks"
	ShadowsocksR ProxyType = "ShadowsocksR"
	Snell        ProxyType = "Snell"
	Socks5       ProxyType = "Socks5"
	Http         ProxyType = "Http"
	Vmess        ProxyType = "Vmess"
	Trojan       ProxyType = "Trojan"

	Vless       ProxyType = "Vless"
	Hysteria    ProxyType = "Hysteria"
	Hysteria2   ProxyType = "Hysteria2"
	TUIC        ProxyType = "TUIC"
	Wireguard   ProxyType = "Wireguard"
	SSH         ProxyType = "SSH"
	Mieru       ProxyType = "Mieru"
	AnyTLS      ProxyType = "AnyTLS"
	Sudoku      ProxyType = "Sudoku"
	Masque      ProxyType = "Masque"
	TrustTunnel ProxyType = "TrustTunnel"
	GostRelay   ProxyType = "GostRelay"
	ShadowQuic  ProxyType = "ShadowQuic"
	X365        ProxyType = "X365"
	Miu         ProxyType = "Miu"
	// OpenVPN support is currently treated as experimental in miaospeed.
	OpenVPN ProxyType = "OpenVPN"

	ProxyInvalid ProxyType = "Invalid"
)

var AllProxyTypes = []ProxyType{
	Shadowsocks, ShadowsocksR, Snell, Socks5, Http, Vmess, Trojan,
	Vless, Hysteria, Hysteria2, TUIC, Wireguard, SSH, Mieru, AnyTLS, Sudoku, Masque, TrustTunnel, GostRelay, ShadowQuic, X365, Miu, OpenVPN,
}

func (pt *ProxyType) Equal(other ProxyType) bool {
	ptStr := strings.ToLower(string(*pt))
	otherStr := strings.ToLower(string(other))
	return ptStr == otherStr
}

func Valid(proxyType ProxyType) bool {
	for _, pt := range AllProxyTypes {
		if pt.Equal(proxyType) {
			return true
		}
	}
	return false
}

func Parse(proxyType string) ProxyType {
	pType := ProxyType(proxyType)
	if Valid(pType) {
		return pType
	}
	return ProxyInvalid
}

type ProxyInfo struct {
	Name    string
	Address string
	Type    ProxyType
}

func (pi *ProxyInfo) Map() map[string]string {
	return map[string]string{
		"Name":    pi.Name,
		"Address": pi.Address,
		"Type":    string(pi.Type),
	}
}
