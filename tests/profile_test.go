package tests

import (
	"encoding/base64"
	"fmt"
	"net"
	"testing"

	"github.com/airportr/miaospeed/vendors/clash"
	mdns "github.com/miekg/dns"
)

func startLocalDNSServerForProfileTest(t *testing.T) (addr string, closeFn func()) {
	t.Helper()

	handler := mdns.NewServeMux()
	handler.HandleFunc(".", func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := &mdns.Msg{}
		resp.SetReply(req)

		for _, question := range req.Question {
			switch question.Qtype {
			case mdns.TypeA:
				resp.Answer = append(resp.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: question.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30},
					A:   net.ParseIP("198.51.100.42").To4(),
				})
			case mdns.TypeAAAA:
				resp.Answer = append(resp.Answer, &mdns.AAAA{
					Hdr:  mdns.RR_Header{Name: question.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 30},
					AAAA: net.ParseIP("2001:db8::42"),
				})
			}
		}

		_ = w.WriteMsg(resp)
	})

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local dns server: %v", err)
	}

	server := &mdns.Server{
		PacketConn: packetConn,
		Handler:    handler,
	}
	go func() {
		_ = server.ActivateAndServe()
	}()

	return packetConn.LocalAddr().String(), func() {
		_ = server.Shutdown()
		_ = packetConn.Close()
	}
}

func buildMihomoDNSConfigToken(nameServer string) string {
	config := fmt.Sprintf(`dns:
  enable: true
  ipv6: true
  nameserver:
    - %s
  default-nameserver:
    - 127.0.0.1
`, nameServer)
	return "mihomo://" + base64.StdEncoding.EncodeToString([]byte(config))
}

func TestApplyMihomoDNSForProxyServer_RewriteServerAndPreserveDomain(t *testing.T) {
	nameServer, closeFn := startLocalDNSServerForProfileTest(t)
	defer closeFn()

	payload := map[string]any{
		"type":   "trojan",
		"server": "example.com",
	}
	token := buildMihomoDNSConfigToken(nameServer)
	clash.ApplyMihomoDNSForProxyServerForTest(payload, []string{token})

	if got, _ := payload["server"].(string); got != "198.51.100.42" {
		t.Fatalf("expected rewritten proxy server IP, got %q", got)
	}
	if got, _ := payload["sni"].(string); got != "example.com" {
		t.Fatalf("expected sni preserved as original domain, got %q", got)
	}
	if got, _ := payload["servername"].(string); got != "example.com" {
		t.Fatalf("expected servername preserved as original domain, got %q", got)
	}
}

func TestApplyMihomoDNSForProxyServer_KeepExistingSNI(t *testing.T) {
	nameServer, closeFn := startLocalDNSServerForProfileTest(t)
	defer closeFn()

	payload := map[string]any{
		"type":       "trojan",
		"server":     "example.com",
		"sni":        "preset.example",
		"servername": "preset.servername",
	}
	token := buildMihomoDNSConfigToken(nameServer)
	clash.ApplyMihomoDNSForProxyServerForTest(payload, []string{token})

	if got, _ := payload["server"].(string); got != "198.51.100.42" {
		t.Fatalf("expected rewritten proxy server IP, got %q", got)
	}
	if got, _ := payload["sni"].(string); got != "preset.example" {
		t.Fatalf("expected existing sni to remain, got %q", got)
	}
	if got, _ := payload["servername"].(string); got != "preset.servername" {
		t.Fatalf("expected existing servername to remain, got %q", got)
	}
}

func TestApplyMihomoDNSForProxyServer_NoMihomoTokenNoChange(t *testing.T) {
	payload := map[string]any{
		"type":   "trojan",
		"server": "example.com",
	}
	clash.ApplyMihomoDNSForProxyServerForTest(payload, []string{"8.8.8.8", "https://dns.google/dns-query"})

	if got, _ := payload["server"].(string); got != "example.com" {
		t.Fatalf("expected server unchanged without mihomo token, got %q", got)
	}
	if _, ok := payload["sni"]; ok {
		t.Fatalf("did not expect sni to be set when no mihomo token matched")
	}
}
