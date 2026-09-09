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
}

// startMockPanel runs a websocket server that plays the client/panel role of
// the reverse-connection protocol: it accepts an outbound dialed connection,
// validates the ReverseHello and replies a ReverseAck. With closeAfterAck the
// connection is dropped right after the handshake, forcing miaospeed to
// reconnect (chaos mode).
func startMockPanel(t *testing.T, token string, closeAfterAck bool) *mockPanel {
	t.Helper()

	panel := &mockPanel{Conns: make(chan *websocket.Conn, 64)}
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(rw, r, nil)
		if err != nil {
			return
		}
		panel.accepted.Add(1)

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
		ack := &interfaces.ReverseAck{
			Type:      interfaces.ReverseMsgAck,
			Protocol:  interfaces.ReverseProtocolV1,
			Sign:      utils.SignChallenge(token, hello.Sign),
			Version:   "test",
			Name:      "mock-panel",
			SessionID: utils.RandomUUID(),
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

// TestReverseConnectTaskRoundTrip covers the whole reverse path: outbound
// dial, msr-v1 handshake, then a signed SlaveRequest that must come back
// as progress + result over the same connection.
func TestReverseConnectTaskRoundTrip(t *testing.T) {
	ensureTaskServer()

	token := "reverse-test-token"
	origToken, origURL := utils.GCFG.Token, utils.GCFG.ConnectURL
	utils.GCFG.Token = token
	defer func() {
		utils.GCFG.Token, utils.GCFG.ConnectURL = origToken, origURL
	}()

	panel := startMockPanel(t, token, false)
	utils.GCFG.ConnectURL = panel.URL
	go service.RunReverseConnector()

	var conn *websocket.Conn
	select {
	case conn = <-panel.Conns:
	case <-time.After(20 * time.Second):
		t.Fatalf("no reverse connection established, accepted=%d", panel.accepted.Load())
	}

	sr := interfaces.SlaveRequest{
		Basics: interfaces.SlaveRequestBasics{
			ID:      "reverse-task-1",
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
		if resp.Result.Request.Basics.ID != "reverse-task-1" {
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
		break
	}
}

// TestReverseConnectReconnect drops every connection right after the
// handshake and expects the connector to keep coming back.
func TestReverseConnectReconnect(t *testing.T) {
	ensureTaskServer()

	token := "reverse-chaos-token"
	origToken, origURL := utils.GCFG.Token, utils.GCFG.ConnectURL
	utils.GCFG.Token = token
	defer func() {
		utils.GCFG.Token, utils.GCFG.ConnectURL = origToken, origURL
	}()

	panel := startMockPanel(t, token, true)
	utils.GCFG.ConnectURL = panel.URL
	go service.RunReverseConnector()

	// 4 pooled workers each reconnecting after 1s/2s/4s... backoff should
	// easily produce 6 handshakes within 30s.
	deadline := time.Now().Add(30 * time.Second)
	for panel.accepted.Load() < 6 {
		if time.Now().After(deadline) {
			t.Fatalf("expected reconnects after dropped links, accepted=%d", panel.accepted.Load())
		}
		time.Sleep(100 * time.Millisecond)
	}
}
