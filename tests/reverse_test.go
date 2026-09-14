package tests

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/service"
	"github.com/airportr/miaospeed/utils"
	"github.com/gorilla/websocket"
)

var taskServerOnce sync.Once

func ensureTaskServer() {
	taskServerOnce.Do(func() {
		go service.StartTaskServer()
	})
}

type mockPanel struct {
	URL      string
	Conns    chan *websocket.Conn
	accepted atomic.Int64
	// pools is the connection count negotiated on the n-th handshake, the last
	// entry repeating. Empty means the client negotiates nothing (Pool stays 0).
	pools []int
}

// startMockPanel runs a websocket server that plays the client/panel role of
// the reverse-connection protocol: it accepts an outbound dialed connection,
// validates the ReverseHello and replies a ReverseAck. With closeAfterAck the
// connection is dropped right after the handshake, forcing miaospeed to
// reconnect (chaos mode).
func startMockPanel(t *testing.T, token string, closeAfterAck bool) *mockPanel {
	t.Helper()
	return startMockPanelWithPools(t, token, closeAfterAck)
}

// startMockPanelWithPools is startMockPanel with a scripted sequence of
// negotiated pool sizes, one entry per accepted handshake.
func startMockPanelWithPools(t *testing.T, token string, closeAfterAck bool, pools ...int) *mockPanel {
	t.Helper()

	panel := &mockPanel{Conns: make(chan *websocket.Conn, 64), pools: pools}
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		handshake := int(panel.accepted.Add(1)) - 1

		hello := interfaces.ReverseHello{}
		if err := conn.ReadJSON(&hello); err != nil {
			_ = conn.Close()
			return
		}
		expect := utils.SignChallenge(token, fmt.Sprintf("reverse-hello|%s|%d", hello.Nonce, hello.Timestamp))
		if hello.Type != interfaces.ReverseMsgHello || hello.Protocol != interfaces.ReverseProtocolV1 || hello.Sign != expect {
			_ = conn.WriteJSON(&interfaces.ReverseAck{Type: interfaces.ReverseMsgError, Error: "invalid hello"})
			_ = conn.Close()
			return
		}
		pool := 0
		if len(panel.pools) > 0 {
			pool = panel.pools[min(handshake, len(panel.pools)-1)]
		}
		ack := &interfaces.ReverseAck{
			Type:      interfaces.ReverseMsgAck,
			Protocol:  interfaces.ReverseProtocolV1,
			Sign:      utils.SignChallenge(token, hello.Sign),
			Version:   "test",
			Name:      "mock-panel",
			SessionID: utils.RandomUUID(),
			Pool:      pool,
		}
		if err := conn.WriteJSON(ack); err != nil {
			_ = conn.Close()
			return
		}
		if closeAfterAck {
			_ = conn.Close()
			return
		}
		select {
		case panel.Conns <- conn:
		default:
			_ = conn.Close()
			return
		}
		// The test goroutine becomes the sole reader of this connection;
		// do not read here or the two readers would corrupt the stream.
	}))
	panel.URL = "ws" + strings.TrimPrefix(srv.URL, "http") + "/reverse"
	t.Cleanup(srv.Close)
	return panel
}

// withReverseGlobals pins the token and the reverse endpoints for one test and
// restores the previous values afterwards. Use withLegacyConnectURL to cover the
// deprecated single endpoint field instead.
func withReverseGlobals(t *testing.T, token string, endpoints ...string) {
	t.Helper()
	origToken, origURL, origURLs := utils.GCFG.Token, utils.GCFG.ConnectURL, utils.GCFG.ConnectURLs
	utils.GCFG.Token = token
	utils.GCFG.ConnectURL = ""
	utils.GCFG.ConnectURLs = endpoints
	t.Cleanup(func() {
		utils.GCFG.Token, utils.GCFG.ConnectURL, utils.GCFG.ConnectURLs = origToken, origURL, origURLs
	})
}

// withLegacyConnectURL pins only the deprecated single endpoint field, which
// covers the ConnectEndpoints fallback older callers rely on.
func withLegacyConnectURL(t *testing.T, token, rawURL string) {
	t.Helper()
	origToken, origURL, origURLs := utils.GCFG.Token, utils.GCFG.ConnectURL, utils.GCFG.ConnectURLs
	utils.GCFG.Token = token
	utils.GCFG.ConnectURL = rawURL
	utils.GCFG.ConnectURLs = nil
	t.Cleanup(func() {
		utils.GCFG.Token, utils.GCFG.ConnectURL, utils.GCFG.ConnectURLs = origToken, origURL, origURLs
	})
}

// waitForPanelConn waits for one accepted reverse connection of a panel.
func waitForPanelConn(t *testing.T, panel *mockPanel, timeout time.Duration) *websocket.Conn {
	t.Helper()
	select {
	case conn := <-panel.Conns:
		return conn
	case <-time.After(timeout):
		t.Fatalf("no reverse connection established, accepted=%d", panel.accepted.Load())
		return nil
	}
}

// waitAccepted blocks until the panel saw at least want handshakes.
func waitAccepted(t *testing.T, panel *mockPanel, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for panel.accepted.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("expected at least %d accepted connections, got %d", want, panel.accepted.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// assertAcceptedStable asserts the handshake count settled on want, i.e. the
// connector neither keeps growing nor redials a healthy pool.
func assertAcceptedStable(t *testing.T, panel *mockPanel, want int64, settle time.Duration) {
	t.Helper()
	time.Sleep(settle)
	if got := panel.accepted.Load(); got != want {
		t.Fatalf("expected the pool to settle at %d connections, got %d", want, got)
	}
}

// buildInvalidTask builds a signed request running the "invalid" matrix, the
// cheapest possible full round trip.
func buildInvalidTask(token, id string) interfaces.SlaveRequest {
	sr := interfaces.SlaveRequest{
		Basics: interfaces.SlaveRequestBasics{
			ID:      id,
			Invoker: "test-bot",
			Slave:   "mock",
			Version: "test",
		},
		Options: interfaces.SlaveRequestOptions{
			Matrices: []interfaces.SlaveRequestMatrixEntry{{Type: interfaces.MatrixInvalid}},
		},
		Vendor: interfaces.VendorLocal,
		Nodes:  []interfaces.SlaveRequestNode{{Name: "direct", Payload: ""}},
	}
	sr.Configs.SlaveRequestConfigsV2 = &interfaces.SlaveRequestConfigsV2{
		SlaveRequestConfigsV1: &interfaces.SlaveRequestConfigsV1{},
		ApiVersion:            interfaces.ApiV2,
	}
	sr.Challenge = utils.SignRequest(token, &sr)
	return sr
}

// runTaskOverReverseLink sends one signed request and requires progress before
// the final result, proving the link serves the full miaospeed protocol.
func runTaskOverReverseLink(t *testing.T, conn *websocket.Conn, sr interfaces.SlaveRequest) {
	t.Helper()

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteJSON(&sr); err != nil {
		t.Fatalf("send request over reverse link: %s", err.Error())
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	sawProgress := false
	for {
		var resp interfaces.SlaveResponse
		if err := conn.ReadJSON(&resp); err != nil {
			t.Fatalf("read response over reverse link (progress=%v): %s", sawProgress, err.Error())
		}
		if resp.Error != "" {
			t.Fatalf("backend returned an error: %s", resp.Error)
		}
		if resp.Progress != nil {
			sawProgress = true
			continue
		}
		if resp.Result == nil {
			continue
		}
		if resp.Result.Request.Basics.ID != sr.Basics.ID {
			t.Fatalf("result echoes the wrong task id: %s", resp.Result.Request.Basics.ID)
		}
		if !sawProgress {
			t.Fatal("no progress message received before the final result")
		}
		if len(resp.Result.Results) != 1 {
			t.Fatalf("expected 1 result entry, got %d", len(resp.Result.Results))
		}
		if resp.Result.Results[0].ProxyInfo.Name != "direct" {
			t.Fatalf("unexpected node name in result: %s", resp.Result.Results[0].ProxyInfo.Name)
		}
		return
	}
}

func TestSplitConnectValues(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"single", "wss://a/reverse", []string{"wss://a/reverse"}},
		{"comma", "wss://a/reverse,wss://b/reverse", []string{"wss://a/reverse", "wss://b/reverse"}},
		{"whitespace", "  wss://a/reverse ,  wss://b/reverse  ", []string{"wss://a/reverse", "wss://b/reverse"}},
		{"empty parts", "wss://a/reverse,,  ,wss://b/reverse", []string{"wss://a/reverse", "wss://b/reverse"}},
		{"blank", "   ", []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := utils.SplitConnectValues(c.raw)
			if len(got) != len(c.want) {
				t.Fatalf("SplitConnectValues(%q) = %v, want %v", c.raw, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("SplitConnectValues(%q) = %v, want %v", c.raw, got, c.want)
				}
			}
		})
	}
}

func TestParseConnectEndpoints(t *testing.T) {
	valid, rejected, duplicated := utils.ParseConnectEndpoints([]string{
		"wss://panel-a.example.com/reverse",
		"  wss://panel-a.example.com/reverse  ", // duplicate after trimming
		"WSS://Panel-B.example.com/reverse",     // scheme and host are case insensitive
		"http://panel-c.example.com/reverse",    // wrong scheme
		"wss://",                                // missing host
		"",                                      // ignored
	})

	want := []string{
		"wss://panel-a.example.com/reverse",
		"wss://panel-b.example.com/reverse",
	}
	if len(valid) != len(want) {
		t.Fatalf("valid = %v, want %v", valid, want)
	}
	for i := range want {
		if valid[i] != want[i] {
			t.Fatalf("valid = %v, want %v", valid, want)
		}
	}
	if len(duplicated) != 1 {
		t.Fatalf("duplicated = %v, want exactly one entry", duplicated)
	}
	if len(rejected) != 2 {
		t.Fatalf("rejected = %v, want exactly two entries", rejected)
	}
}

// TestReverseConnectTaskRoundTrip covers the whole reverse path over the
// deprecated single endpoint field: outbound dial, msr-v1 handshake, then a
// signed SlaveRequest that must come back as progress + result.
func TestReverseConnectTaskRoundTrip(t *testing.T) {
	ensureTaskServer()

	token := "reverse-test-token"
	panel := startMockPanel(t, token, false)
	withLegacyConnectURL(t, token, panel.URL)
	go service.RunReverseConnector()

	conn := waitForPanelConn(t, panel, 20*time.Second)
	runTaskOverReverseLink(t, conn, buildInvalidTask(token, "reverse-task-1"))
}

// TestReverseConnectReconnect drops every connection right after the handshake
// and expects the connector to keep coming back. The panel negotiates a pool of
// 4 so the original "several workers retry in parallel" coverage is preserved
// now that the default pool is 1.
func TestReverseConnectReconnect(t *testing.T) {
	ensureTaskServer()

	token := "reverse-chaos-token"
	panel := startMockPanelWithPools(t, token, true, 4)
	withLegacyConnectURL(t, token, panel.URL)
	go service.RunReverseConnector()

	// 4 workers each reconnecting after 1s/2s/4s... backoff should easily
	// produce 6 handshakes within 30s.
	waitAccepted(t, panel, 6, 30*time.Second)
}

// TestReverseConnectMultipleEndpoints is the core of the multi endpoint
// feature: one backend serving two panels at the same time, both usable.
func TestReverseConnectMultipleEndpoints(t *testing.T) {
	ensureTaskServer()

	token := "reverse-multi-token"
	panelA := startMockPanel(t, token, false)
	panelB := startMockPanel(t, token, false)
	withReverseGlobals(t, token, panelA.URL, panelB.URL)
	go service.RunReverseConnector()

	connA := waitForPanelConn(t, panelA, 20*time.Second)
	connB := waitForPanelConn(t, panelB, 20*time.Second)

	runTaskOverReverseLink(t, connA, buildInvalidTask(token, "multi-task-a"))
	runTaskOverReverseLink(t, connB, buildInvalidTask(token, "multi-task-b"))
}

// TestReverseConnectEndpointIsolation proves a dead endpoint does not stop the
// healthy ones: the unusable url is dialed forever in the background while the
// second endpoint must still come up and serve a task.
func TestReverseConnectEndpointIsolation(t *testing.T) {
	ensureTaskServer()

	token := "reverse-isolation-token"
	panel := startMockPanel(t, token, false)
	withReverseGlobals(t, token, "ws://127.0.0.1:1/reverse", panel.URL)
	go service.RunReverseConnector()

	conn := waitForPanelConn(t, panel, 20*time.Second)
	runTaskOverReverseLink(t, conn, buildInvalidTask(token, "isolation-task-1"))
}

// TestReverseConnectNegotiatedPool checks the client can ask for a bigger pool
// through the ReverseAck: one probe connection is dialed, then the pool grows to
// the negotiated size and stops there.
func TestReverseConnectNegotiatedPool(t *testing.T) {
	ensureTaskServer()

	token := "reverse-pool-token"
	panel := startMockPanelWithPools(t, token, false, 3)
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitAccepted(t, panel, 3, 20*time.Second)
	assertAcceptedStable(t, panel, 3, 2*time.Second)
}

// TestReverseConnectPoolIsGrowOnly pins the deliberate one-way behaviour: after
// a client negotiated 3 connections, a later ack asking for 1 must not tear the
// extra sessions down.
func TestReverseConnectPoolIsGrowOnly(t *testing.T) {
	ensureTaskServer()

	token := "reverse-growonly-token"
	panel := startMockPanelWithPools(t, token, false, 3, 1, 1, 1)
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitAccepted(t, panel, 3, 20*time.Second)
	assertAcceptedStable(t, panel, 3, 2*time.Second)
}

// TestReverseConnectDeduplicatesEndpoints ensures the same endpoint given twice
// is only served once, so a copy pasted command cannot double the connections.
func TestReverseConnectDeduplicatesEndpoints(t *testing.T) {
	ensureTaskServer()

	token := "reverse-dedup-token"
	panel := startMockPanel(t, token, false)
	withReverseGlobals(t, token, panel.URL, panel.URL, "  "+panel.URL+"  ")
	go service.RunReverseConnector()

	waitAccepted(t, panel, 1, 20*time.Second)
	assertAcceptedStable(t, panel, 1, 2*time.Second)
}
