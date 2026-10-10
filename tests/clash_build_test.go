package tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/airportr/miaospeed/interfaces"
	clashvendor "github.com/airportr/miaospeed/vendors/clash"
)

func buildClashVendor(proxyName, proxyPayload string) interfaces.Vendor {
	return (&clashvendor.Clash{}).Build(proxyName, proxyPayload)
}

const testPEMCertificate = `-----BEGIN CERTIFICATE-----
AQID
-----END CERTIFICATE-----`

func indentYAMLBlock(block string) string {
	lines := strings.Split(strings.TrimSpace(block), "\n")
	for i, line := range lines {
		lines[i] = "    " + line
	}
	return strings.Join(lines, "\n")
}

func buildOpenVPNTLSCryptBlock() string {
	return fmt.Sprintf(
		"-----BEGIN OpenVPN Static key V1-----\n%s\n-----END OpenVPN Static key V1-----",
		strings.Repeat("00", 256),
	)
}

func TestClashBuild_InvalidYAMLNotReady(t *testing.T) {
	vendor := buildClashVendor("invalid", "name: [")
	if vendor.Status() != interfaces.VStatusNotReady {
		t.Fatalf("expected status %v, got %v", interfaces.VStatusNotReady, vendor.Status())
	}
}

func TestClashBuild_VlessXHTTPReuseSettings(t *testing.T) {
	vendor := buildClashVendor("vless-xhttp", `
name: vless-xhttp
type: vless
server: example.com
port: 443
uuid: 11111111-1111-1111-1111-111111111111
udp: true
tls: true
network: xhttp
servername: example.com
client-fingerprint: chrome
xhttp-opts:
  path: /
  host: example.com
  mode: stream-up
  reuse-settings:
    max-connections: "16-32"
    max-concurrency: "0"
    c-max-reuse-times: "0"
    h-max-request-times: "600-900"
    h-max-reusable-secs: "1800-3000"
`)

	if vendor.Status() != interfaces.VStatusOperational {
		t.Fatalf("expected status %v, got %v", interfaces.VStatusOperational, vendor.Status())
	}

	proxyInfo := vendor.ProxyInfo()
	if proxyInfo.Name != "vless-xhttp" {
		t.Fatalf("expected proxy name vless-xhttp, got %s", proxyInfo.Name)
	}
	if proxyInfo.Type != interfaces.Vless {
		t.Fatalf("expected proxy type %s, got %s", interfaces.Vless, proxyInfo.Type)
	}
}

func TestClashBuild_VmessGrpcExtendedOptions(t *testing.T) {
	vendor := buildClashVendor("vmess-grpc", `
name: vmess-grpc
type: vmess
server: example.com
port: 443
uuid: 11111111-1111-1111-1111-111111111111
alterId: 32
cipher: auto
network: grpc
tls: true
servername: example.com
grpc-opts:
  grpc-service-name: example
  ping-interval: 10
  max-connections: 2
  min-streams: 1
`)

	if vendor.Status() != interfaces.VStatusOperational {
		t.Fatalf("expected status %v, got %v", interfaces.VStatusOperational, vendor.Status())
	}

	proxyInfo := vendor.ProxyInfo()
	if proxyInfo.Name != "vmess-grpc" {
		t.Fatalf("expected proxy name vmess-grpc, got %s", proxyInfo.Name)
	}
	if proxyInfo.Type != interfaces.Vmess {
		t.Fatalf("expected proxy type %s, got %s", interfaces.Vmess, proxyInfo.Type)
	}
}

func TestClashBuild_TrustTunnel(t *testing.T) {
	vendor := buildClashVendor("trusttunnel", `
name: trusttunnel
type: trusttunnel
server: 1.2.3.4
port: 443
username: username
password: password
health-check: true
udp: true
`)

	if vendor.Status() != interfaces.VStatusOperational {
		t.Fatalf("expected status %v, got %v", interfaces.VStatusOperational, vendor.Status())
	}

	proxyInfo := vendor.ProxyInfo()
	if proxyInfo.Name != "trusttunnel" {
		t.Fatalf("expected proxy name trusttunnel, got %s", proxyInfo.Name)
	}
	if proxyInfo.Type != interfaces.TrustTunnel {
		t.Fatalf("expected proxy type %s, got %s", interfaces.TrustTunnel, proxyInfo.Type)
	}
}

func TestClashBuild_Hysteria2RealmOpts(t *testing.T) {
	vendor := buildClashVendor("hysteria2-realm", `
name: hysteria2-realm
type: hysteria2
server: example.com
port: 443
password: yourpassword
sni: example.com
realm-opts:
  enable: true
  server-url: https://realm.example.com
  token: public
  realm-id: my-realm
  stun-servers:
    - stun.nextcloud.com:3478
  skip-cert-verify: true
`)

	if vendor.Status() != interfaces.VStatusOperational {
		t.Fatalf("expected status %v, got %v", interfaces.VStatusOperational, vendor.Status())
	}

	proxyInfo := vendor.ProxyInfo()
	if proxyInfo.Name != "hysteria2-realm" {
		t.Fatalf("expected proxy name hysteria2-realm, got %s", proxyInfo.Name)
	}
	if proxyInfo.Type != interfaces.Hysteria2 {
		t.Fatalf("expected proxy type %s, got %s", interfaces.Hysteria2, proxyInfo.Type)
	}
}

func TestClashBuild_GostRelay(t *testing.T) {
	vendor := buildClashVendor("gost-relay", `
name: gost-relay
type: gost-relay
server: relay.example.com
port: 443
udp: true
tls: true
username: user
password: pass
`)

	if vendor.Status() != interfaces.VStatusOperational {
		t.Fatalf("expected status %v, got %v", interfaces.VStatusOperational, vendor.Status())
	}

	proxyInfo := vendor.ProxyInfo()
	if proxyInfo.Name != "gost-relay" {
		t.Fatalf("expected proxy name gost-relay, got %s", proxyInfo.Name)
	}
	if proxyInfo.Type != interfaces.GostRelay {
		t.Fatalf("expected proxy type %s, got %s", interfaces.GostRelay, proxyInfo.Type)
	}
}

func TestClashBuild_ShadowQuic(t *testing.T) {
	vendor := buildClashVendor("shadowquic", `
name: shadowquic
type: shadowquic
server: example.com
port: 10443
username: username
password: password
`)

	if vendor.Status() != interfaces.VStatusOperational {
		t.Fatalf("expected status %v, got %v", interfaces.VStatusOperational, vendor.Status())
	}

	proxyInfo := vendor.ProxyInfo()
	if proxyInfo.Name != "shadowquic" {
		t.Fatalf("expected proxy name shadowquic, got %s", proxyInfo.Name)
	}
	if proxyInfo.Type != interfaces.ShadowQuic {
		t.Fatalf("expected proxy type %s, got %s", interfaces.ShadowQuic, proxyInfo.Type)
	}
}
func TestClashBuild_OpenVPNExperimental(t *testing.T) {
	vendor := buildClashVendor("openvpn", fmt.Sprintf(`
name: openvpn
type: openvpn
server: vpn.example.com
port: 1194
proto: udp
cipher: AES-256-GCM
auth: SHA256
username: user
password: secret
ca: |
%s
tls-crypt: |
%s
udp: true
`, indentYAMLBlock(testPEMCertificate), indentYAMLBlock(buildOpenVPNTLSCryptBlock())))

	if vendor.Status() != interfaces.VStatusOperational {
		t.Fatalf("expected status %v, got %v", interfaces.VStatusOperational, vendor.Status())
	}

	proxyInfo := vendor.ProxyInfo()
	if proxyInfo.Name != "openvpn" {
		t.Fatalf("expected proxy name openvpn, got %s", proxyInfo.Name)
	}
	if proxyInfo.Type != interfaces.OpenVPN {
		t.Fatalf("expected proxy type %s, got %s", interfaces.OpenVPN, proxyInfo.Type)
	}
}
