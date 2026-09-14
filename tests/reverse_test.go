package tests

import (
	"encoding/json"
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

// controlAckPool is the deliberately oversized Pool a mock control connection
// reports in its ack. A control link is not part of the pool, so the backend has
// to ignore it; if it ever counted, the session count would jump to this value.
const controlAckPool = 9

type mockPanel struct {
	URL   string
	Conns chan *websocket.Conn
	// Control carries the control connections of this panel.
	Control chan *websocket.Conn
	// rawHellos keeps the exact bytes of the hellos the backend sent, so a test
	// can pin what goes on the wire. Entries are dropped rather than blocking the
	// handshake when nobody reads them.
	rawHellos chan string
	// accepted counts every handshake, session and control alike.
	accepted atomic.Int64
	// sessions and controls split that total per role.
	sessions atomic.Int64
	controls atomic.Int64
	// live counts the session connections that are open right now. It only moves
	// when the panel owns the session connections itself.
	live atomic.Int64
	// liveIdx holds the handshake index of every session connection that is open
	// right now. `live` only says how many survived; a test that has to know
	// *which* one a shrink took away reads this instead.
	liveIdx sync.Map
	// pinged carries the handshake index of every session connection the panel
	// drives a heartbeat on, in the order they started pinging.
	pinged chan int
	// controlRejected makes the panel refuse every future control connection, so
	// a test can observe the backend once the client stops managing the pool.
	controlRejected atomic.Bool
	// pools is the connection count negotiated on the n-th session handshake, the
	// last entry repeating. Empty means the client negotiates nothing (Pool stays
	// 0). Control handshakes never negotiate a pool and are not counted.
	pools []int
}

// mockPanelOptions is the full description of a mock panel. The zero value is a
// plain legacy client: no control support, no heartbeat, no pool negotiation.
type mockPanelOptions struct {
	token         string
	closeAfterAck bool
	pools         []int
	// advertiseControl makes every ack carry Control: true, so the backend opens
	// a control link for this endpoint.
	advertiseControl bool
	// ownSessions hands the session connections to the panel instead of the test:
	// the panel becomes their only reader, which is what lets it count live
	// connections and ping. Never combine it with reading panel.Conns.
	ownSessions bool
	// pingEvery and pingTimes drive the client heartbeat the backend uses as its
	// idle signal: the panel pings pingTimes times, pingEvery apart, then goes
	// quiet. pingTimes <= 0 means keep pinging until the connection ends.
	pingEvery time.Duration
	pingTimes int
	// quietFirstSessions leaves the first N session handshakes without a
	// heartbeat. The connections dialed afterwards are then the ones that look
	// in use, which is what a test needs to tell "retire the idle one" apart
	// from "retire the newest one".
	quietFirstSessions int
}

// startMockPanel runs a websocket server that plays the client/panel role of
// the reverse-connection protocol: it accepts an outbound dialed connection,
// validates the ReverseHello and replies a ReverseAck. With closeAfterAck the
// connection is dropped right after the handshake, forcing miaospeed to
// reconnect (chaos mode).
func startMockPanel(t *testing.T, token string, closeAfterAck bool) *mockPanel {
	t.Helper()
	return startMockPanelWith(t, mockPanelOptions{token: token, closeAfterAck: closeAfterAck})
}

// startMockPanelWithPools is startMockPanel with a scripted sequence of
// negotiated pool sizes, one entry per accepted session handshake.
func startMockPanelWithPools(t *testing.T, token string, closeAfterAck bool, pools ...int) *mockPanel {
	t.Helper()
	return startMockPanelWith(t, mockPanelOptions{token: token, closeAfterAck: closeAfterAck, pools: pools})
}

// startMockPanelWith is the full mock panel: it can advertise control support,
// own its session connections, and drive a client heartbeat.
func startMockPanelWith(t *testing.T, opts mockPanelOptions) *mockPanel {
	t.Helper()

	panel := &mockPanel{
		Conns:     make(chan *websocket.Conn, 64),
		Control:   make(chan *websocket.Conn, 8),
		rawHellos: make(chan string, 64),
		pinged:    make(chan int, 8),
		pools:     opts.pools,
	}
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		panel.accepted.Add(1)

		_, data, err := conn.ReadMessage()
		if err != nil {
			_ = conn.Close()
			return
		}
		select {
		case panel.rawHellos <- string(data):
		default: // nobody is inspecting hellos right now
		}
		hello := interfaces.ReverseHello{}
		if err := json.Unmarshal(data, &hello); err != nil {
			_ = conn.Close()
			return
		}
		expect := utils.SignChallenge(opts.token, fmt.Sprintf("reverse-hello|%s|%d", hello.Nonce, hello.Timestamp))
		if hello.Type != interfaces.ReverseMsgHello || hello.Protocol != interfaces.ReverseProtocolV1 || hello.Sign != expect {
			_ = conn.WriteJSON(&interfaces.ReverseAck{Type: interfaces.ReverseMsgError, Error: "invalid hello"})
			_ = conn.Close()
			return
		}

		// An empty or "session" role is a plain task session, exactly what a
		// client predating the control link would send.
		control := hello.Role == interfaces.ReverseRoleControl
		pool := 0
		index := -1
		if control {
			panel.controls.Add(1)
			pool = controlAckPool
			if panel.controlRejected.Load() {
				_ = conn.WriteJSON(&interfaces.ReverseAck{Type: interfaces.ReverseMsgError, Error: "control rejected"})
				_ = conn.Close()
				return
			}
		} else {
			index = int(panel.sessions.Add(1)) - 1
			if len(panel.pools) > 0 {
				pool = panel.pools[min(index, len(panel.pools)-1)]
			}
		}

		ack := &interfaces.ReverseAck{
			Type:      interfaces.ReverseMsgAck,
			Protocol:  interfaces.ReverseProtocolV1,
			Sign:      utils.SignChallenge(opts.token, hello.Sign),
			Version:   "test",
			Name:      "mock-panel",
			SessionID: utils.RandomUUID(),
			Pool:      pool,
			Control:   opts.advertiseControl,
		}
		if err := conn.WriteJSON(ack); err != nil {
			_ = conn.Close()
			return
		}
		if opts.closeAfterAck {
			_ = conn.Close()
			return
		}
		if control {
			// The test drives a control link: it writes ReverseScale and reads
			// the ack, so the panel must not read from this connection.
			select {
			case panel.Control <- conn:
			default:
				_ = conn.Close()
			}
			return
		}
		if opts.ownSessions {
			panel.watchSession(conn, opts, index)
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

// watchSession makes the panel own a session connection: it stays the only
// reader, which is what lets it track liveness for pool assertions, and it
// optionally drives the client heartbeat the backend reads as a sign of life.
func (p *mockPanel) watchSession(conn *websocket.Conn, opts mockPanelOptions, index int) {
	p.live.Add(1)
	p.liveIdx.Store(index, struct{}{})
	go func() {
		defer p.live.Add(-1)
		defer p.liveIdx.Delete(index)
		if opts.pingEvery > 0 && index >= opts.quietFirstSessions {
			select {
			case p.pinged <- index:
			default: // nobody is counting pings right now
			}
			go pingLoop(conn, opts.pingEvery, opts.pingTimes)
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
}

// sessionAlive reports whether the session connection with this handshake index
// is still open, which is what lets a shrink test name the victim.
func (p *mockPanel) sessionAlive(index int) bool {
	_, ok := p.liveIdx.Load(index)
	return ok
}

// pingLoop pings the backend the way a client would. A finite times models a
// client that went quiet, i.e. a connection nobody uses any more.
func pingLoop(conn *websocket.Conn, every time.Duration, times int) {
	for i := 0; times <= 0 || i < times; i++ {
		time.Sleep(every)
		if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second)); err != nil {
			return
		}
	}
}

// stopControl makes the panel refuse every future control connection, so a test
// can watch the backend resume managing the pool on its own.
func (p *mockPanel) stopControl() {
	p.controlRejected.Store(true)
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

// waitLive blocks until the panel sees exactly want live session connections.
// Unlike the handshake counters this one goes down when the backend retires a
// connection, which is what the shrink tests assert on.
func waitLive(t *testing.T, panel *mockPanel, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for panel.live.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("expected %d live session connections, got %d (sessions=%d controls=%d)",
				want, panel.live.Load(), panel.sessions.Load(), panel.controls.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// assertLiveStable asserts the live session count settled on want, i.e. the
// backend neither grew nor shrank the pool while nothing asked it to.
func assertLiveStable(t *testing.T, panel *mockPanel, want int64, settle time.Duration) {
	t.Helper()
	time.Sleep(settle)
	if got := panel.live.Load(); got != want {
		t.Fatalf("expected the live pool to settle at %d connections, got %d", want, got)
	}
}

// waitForControlConn waits for one accepted control connection of a panel.
func waitForControlConn(t *testing.T, panel *mockPanel, timeout time.Duration) *websocket.Conn {
	t.Helper()
	select {
	case conn := <-panel.Control:
		return conn
	case <-time.After(timeout):
		t.Fatalf("no reverse control link established, controls=%d", panel.controls.Load())
		return nil
	}
}

// waitForRawHello returns the raw bytes of one hello the backend sent.
func waitForRawHello(t *testing.T, panel *mockPanel, timeout time.Duration) string {
	t.Helper()
	select {
	case raw := <-panel.rawHellos:
		return raw
	case <-time.After(timeout):
		t.Fatal("no reverse hello received")
		return ""
	}
}

// scalePool sends one ReverseScale over a control link and returns the ack the
// backend replied, requiring the sequence number to be echoed back.
func scalePool(t *testing.T, conn *websocket.Conn, pool int, seq int64) interfaces.ReverseScaleAck {
	t.Helper()

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteJSON(&interfaces.ReverseScale{Type: interfaces.ReverseMsgScale, Pool: pool, Seq: seq}); err != nil {
		t.Fatalf("send ReverseScale: %s", err.Error())
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var ack interfaces.ReverseScaleAck
	if err := conn.ReadJSON(&ack); err != nil {
		t.Fatalf("read ReverseScaleAck: %s", err.Error())
	}
	if ack.Type != interfaces.ReverseMsgScale {
		t.Fatalf("unexpected ack type %q", ack.Type)
	}
	if ack.Seq != seq {
		t.Fatalf("ack seq = %d, want %d", ack.Seq, seq)
	}
	if ack.Error != "" {
		t.Fatalf("backend rejected ReverseScale: %s", ack.Error)
	}
	return ack
}

// withShortReverseIdleTimeout shortens the autonomous shrink threshold for one
// test so it does not have to wait five minutes, and restores the production
// value afterwards.
func withShortReverseIdleTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	previous := service.SetReverseIdleTimeoutForTest(d)
	t.Cleanup(func() { service.SetReverseIdleTimeoutForTest(previous) })
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

// TestReverseConnectHelloRole pins what goes on the wire: a session hello must
// stay byte identical to the one older clients already parse, so Role is absent
// unless the connection really is a control link.
func TestReverseConnectHelloRole(t *testing.T) {
	ensureTaskServer()

	token := "reverse-role-token"
	panel := startMockPanelWith(t, mockPanelOptions{
		token:            token,
		advertiseControl: true,
		ownSessions:      true,
	})
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitLive(t, panel, 1, 20*time.Second)
	waitForControlConn(t, panel, 20*time.Second)

	// Two hellos, one per role, in either order.
	roles := map[string]string{}
	for i := 0; i < 2; i++ {
		raw := waitForRawHello(t, panel, 20*time.Second)
		var hello interfaces.ReverseHello
		if err := json.Unmarshal([]byte(raw), &hello); err != nil {
			t.Fatalf("hello is not valid json: %s", raw)
		}
		if strings.Contains(raw, `"Role":""`) {
			t.Fatalf("an empty Role must never be serialized, got %s", raw)
		}
		roles[hello.Role] = raw
	}
	if _, ok := roles[interfaces.ReverseRoleControl]; !ok {
		t.Fatalf("no control hello seen, got %v", roles)
	}
	if _, ok := roles[""]; !ok {
		t.Fatalf("no session hello seen, got %v", roles)
	}
	if !strings.Contains(roles[interfaces.ReverseRoleControl], `"Role":"control"`) {
		t.Fatalf("control hello must carry its role, got %s", roles[interfaces.ReverseRoleControl])
	}
}

// TestReverseConnectControlAckPoolIsIgnored pins the protocol rule that a control
// link is not part of the pool: the mock reports controlAckPool on the control
// handshake and the session pool must stay at its default of one.
func TestReverseConnectControlAckPoolIsIgnored(t *testing.T) {
	ensureTaskServer()

	token := "reverse-controlpool-token"
	panel := startMockPanelWith(t, mockPanelOptions{
		token:            token,
		advertiseControl: true,
		ownSessions:      true,
	})
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitLive(t, panel, 1, 20*time.Second)
	waitForControlConn(t, panel, 20*time.Second)
	assertLiveStable(t, panel, 1, 500*time.Millisecond)
}

// TestReverseConnectControlGrowShrink covers the control channel end to end: the
// client resizes the pool at any time, in both directions, and the ack reports
// what was applied.
func TestReverseConnectControlGrowShrink(t *testing.T) {
	ensureTaskServer()
	withShortReverseIdleTimeout(t, 500*time.Millisecond)

	token := "reverse-control-token"
	panel := startMockPanelWith(t, mockPanelOptions{
		token:            token,
		advertiseControl: true,
		ownSessions:      true,
		pingEvery:        20 * time.Millisecond,
		pingTimes:        3, // alive during the handshake, quiet afterwards
	})
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitLive(t, panel, 1, 20*time.Second)
	control := waitForControlConn(t, panel, 20*time.Second)

	if got := scalePool(t, control, 3, 1).Pool; got != 3 {
		t.Fatalf("ReverseScale{Pool:3} applied %d, want 3", got)
	}
	waitLive(t, panel, 3, 20*time.Second)

	if got := scalePool(t, control, 1, 2).Pool; got != 1 {
		t.Fatalf("ReverseScale{Pool:1} applied %d, want 1", got)
	}
	waitLive(t, panel, 1, 20*time.Second)
	// The floor holds even though every connection is idle by now.
	assertLiveStable(t, panel, 1, 700*time.Millisecond)
}

// TestReverseConnectControlShrinkWithPingingClient pins the fix in 8cd6664: a
// client that keeps pinging, so the autonomous idle gate can never expire, must
// still see a shrink it asked for applied at once. Every other shrink test lets
// its client fall silent right after the handshake, which is exactly why they
// passed before the fix and could never have caught it: the gate was already
// open when they shrunk.
func TestReverseConnectControlShrinkWithPingingClient(t *testing.T) {
	ensureTaskServer()
	withShortReverseIdleTimeout(t, 500*time.Millisecond)

	token := "reverse-pingshrink-token"
	panel := startMockPanelWith(t, mockPanelOptions{
		token:            token,
		pools:            []int{3},
		advertiseControl: true,
		ownSessions:      true,
		pingEvery:        20 * time.Millisecond,
		pingTimes:        -1, // keeps pinging, like a client that is still busy
	})
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitLive(t, panel, 3, 20*time.Second)
	control := waitForControlConn(t, panel, 20*time.Second)

	// Well past the idle threshold: only the pings keep these connections alive,
	// so nothing has been retired on the backend's own initiative by now.
	assertLiveStable(t, panel, 3, 1200*time.Millisecond)

	if got := scalePool(t, control, 1, 1).Pool; got != 1 {
		t.Fatalf("ReverseScale{Pool:1} applied %d, want 1", got)
	}
	waitLive(t, panel, 1, 20*time.Second)
	assertLiveStable(t, panel, 1, 700*time.Millisecond)
}

// TestReverseConnectShrinkRetiresTheIdleConnection pins which connection a
// client-requested shrink takes away. The backend cannot see task activity
// (handleWsSession is shared with the inbound listener), so the client ping is
// the only signal it has, and the connection nobody is pinging any more is the
// one that should go, since the other one may be carrying a task. Retiring the
// newest slot instead, which is what the code used to do, takes away exactly
// the connection that is in use here.
func TestReverseConnectShrinkRetiresTheIdleConnection(t *testing.T) {
	ensureTaskServer()
	withShortReverseIdleTimeout(t, 500*time.Millisecond)

	token := "reverse-idlevictim-token"
	panel := startMockPanelWith(t, mockPanelOptions{
		token:              token,
		advertiseControl:   true,
		ownSessions:        true,
		pingEvery:          20 * time.Millisecond,
		pingTimes:          -1,
		quietFirstSessions: 1,
	})
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitLive(t, panel, 1, 20*time.Second)
	control := waitForControlConn(t, panel, 20*time.Second)

	// The probe connection is the quiet one, so the connection dialed for this
	// grow is the one that looks in use, and it is also the newest slot.
	if got := scalePool(t, control, 2, 1).Pool; got != 2 {
		t.Fatalf("ReverseScale{Pool:2} applied %d, want 2", got)
	}
	waitLive(t, panel, 2, 20*time.Second)
	pinger := <-panel.pinged

	// Let the two drift apart: one keeps reporting in, one has gone silent.
	time.Sleep(300 * time.Millisecond)

	if got := scalePool(t, control, 1, 2).Pool; got != 1 {
		t.Fatalf("ReverseScale{Pool:1} applied %d, want 1", got)
	}
	waitLive(t, panel, 1, 20*time.Second)
	assertLiveStable(t, panel, 1, 700*time.Millisecond)
	if !panel.sessionAlive(pinger) {
		t.Fatalf("the shrink retired session %d, the one whose client kept pinging; "+
			"it must spare the connection that still looks in use", pinger)
	}
}

// TestReverseConnectControlClampsPool checks out of range ReverseScale values are
// clamped and the ack reports the value that really took effect.
func TestReverseConnectControlClampsPool(t *testing.T) {
	ensureTaskServer()
	withShortReverseIdleTimeout(t, 500*time.Millisecond)

	token := "reverse-clamp-token"
	panel := startMockPanelWith(t, mockPanelOptions{
		token:            token,
		advertiseControl: true,
		ownSessions:      true,
	})
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitLive(t, panel, 1, 20*time.Second)
	control := waitForControlConn(t, panel, 20*time.Second)

	if got := scalePool(t, control, 0, 1).Pool; got != 1 {
		t.Fatalf("ReverseScale{Pool:0} applied %d, want the floor of 1", got)
	}
	if got := scalePool(t, control, 99, 2).Pool; got != 16 {
		t.Fatalf("ReverseScale{Pool:99} applied %d, want the hard max of 16", got)
	}
	waitLive(t, panel, 16, 20*time.Second)

	if got := scalePool(t, control, -5, 3).Pool; got != 1 {
		t.Fatalf("ReverseScale{Pool:-5} applied %d, want the floor of 1", got)
	}
	waitLive(t, panel, 1, 20*time.Second)
}

// TestReverseConnectAutonomousShrink covers the backend shrinking a pool nobody
// manages: with no control link, idle sessions retire on their own, and the last
// one is always kept.
func TestReverseConnectAutonomousShrink(t *testing.T) {
	ensureTaskServer()
	withShortReverseIdleTimeout(t, 500*time.Millisecond)

	token := "reverse-autoshrink-token"
	panel := startMockPanelWith(t, mockPanelOptions{
		token:       token,
		pools:       []int{3},
		ownSessions: true,
		pingEvery:   20 * time.Millisecond,
		pingTimes:   3, // the client was alive, then went quiet
	})
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitLive(t, panel, 3, 20*time.Second)
	waitLive(t, panel, 1, 20*time.Second)
	// The floor holds: the last session is never retired.
	assertLiveStable(t, panel, 1, 700*time.Millisecond)
}

// TestReverseConnectAutonomousShrinkSparesActiveSessions pins the other half of
// the shrink contract: a connection that keeps showing signs of life, which is
// what a client still using it does, is never retired.
func TestReverseConnectAutonomousShrinkSparesActiveSessions(t *testing.T) {
	ensureTaskServer()
	withShortReverseIdleTimeout(t, 300*time.Millisecond)

	token := "reverse-active-token"
	panel := startMockPanelWith(t, mockPanelOptions{
		token:       token,
		pools:       []int{3},
		ownSessions: true,
		pingEvery:   20 * time.Millisecond,
		pingTimes:   -1, // keep pinging, like a client that is still busy
	})
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitLive(t, panel, 3, 20*time.Second)
	// Well past the idle threshold: only the pings keep the pool alive.
	assertLiveStable(t, panel, 3, 1200*time.Millisecond)
}

// TestReverseConnectAutonomousShrinkNeedsPings pins the safety gate: a client
// that never pings is never shrunk on the backend's own initiative, because the
// backend cannot tell an unused connection from a busy one.
func TestReverseConnectAutonomousShrinkNeedsPings(t *testing.T) {
	ensureTaskServer()
	withShortReverseIdleTimeout(t, 300*time.Millisecond)

	token := "reverse-noping-token"
	panel := startMockPanelWith(t, mockPanelOptions{
		token:       token,
		pools:       []int{3},
		ownSessions: true, // no heartbeat at all
	})
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitLive(t, panel, 3, 20*time.Second)
	assertLiveStable(t, panel, 3, 1200*time.Millisecond)
}

// TestReverseConnectControlSuspendsAutonomousShrink covers the conflict rule:
// while the client manages the pool through a control link the backend does not
// shrink on its own, and it resumes as soon as that link is gone.
func TestReverseConnectControlSuspendsAutonomousShrink(t *testing.T) {
	ensureTaskServer()
	withShortReverseIdleTimeout(t, 500*time.Millisecond)

	token := "reverse-abrule-token"
	panel := startMockPanelWith(t, mockPanelOptions{
		token:            token,
		pools:            []int{3},
		advertiseControl: true,
		ownSessions:      true,
		pingEvery:        20 * time.Millisecond,
		pingTimes:        3,
	})
	withReverseGlobals(t, token, panel.URL)
	go service.RunReverseConnector()

	waitLive(t, panel, 3, 20*time.Second)
	control := waitForControlConn(t, panel, 20*time.Second)

	// The connections have been quiet for longer than the idle threshold, but the
	// client is in charge, so the backend keeps them all.
	assertLiveStable(t, panel, 3, 900*time.Millisecond)

	// The client stops managing: the backend resumes shrinking on its own.
	panel.stopControl()
	_ = control.Close()
	waitLive(t, panel, 1, 20*time.Second)
	assertLiveStable(t, panel, 1, 700*time.Millisecond)
}
