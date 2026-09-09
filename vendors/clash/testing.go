package clash

// ApplyMihomoDNSForProxyServerForTest exposes proxy-server DNS rewriting to cross-package tests.
func ApplyMihomoDNSForProxyServerForTest(payload map[string]any, dnsServers []string) {
	applyMihomoDNSForProxyServer(payload, dnsServers)
}
