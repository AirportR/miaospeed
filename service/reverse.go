package service

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/utils"
	"github.com/gorilla/websocket"
)

// The reverse connector keeps a pool of outbound websocket connections to the
// client/panel (see `-connect`). Each connection is an independent miaospeed
// session identical to the inbound listener; lost connections are re-dialed
// with exponential backoff.
//
// Several endpoints may be served at once. Every endpoint owns a supervisor
// goroutine and its own pool, so an endpoint that is unreachable only costs its
// own connections. The pool size of an endpoint is negotiated by the client:
// the first (probe) connection is always dialed, and the Pool field of its
// ReverseAck decides how many more connections that endpoint should keep.

const (
	// reverseDefaultPoolSize is the pool used until the client negotiates a
	// bigger one, and also what a client asking for less ends up with.
	reverseDefaultPoolSize = 1
	// reversePoolHardMax caps what a client may negotiate through ReverseAck.
	reversePoolHardMax = 16

	reverseHeartbeatSecs = 30
	reverseDialTimeout   = 15 * time.Second
	reverseBackoffBase   = 1 * time.Second
	reverseBackoffMax    = 60 * time.Second

	// reverseStableLink: a link alive this long resets the backoff curve on loss.
	reverseStableLink = 30 * time.Second

	// Clamp the client-requested heartbeat so it can neither force a ping
	// storm nor push the read window past useful liveness detection.
	reverseHeartbeatMinSecs = 10
	reverseHeartbeatMaxSecs = 300
)

var reverseDialer = websocket.Dialer{
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
	HandshakeTimeout: reverseDialTimeout,
}

// reverseHandshakeSign signs the msr-v1 handshake payload
// "reverse-hello|nonce|timestamp" with the shared token.
func reverseHandshakeSign(token, nonce string, timestamp int64) string {
	return utils.SignChallenge(token, fmt.Sprintf("reverse-hello|%s|%d", nonce, timestamp))
}

// RunReverseConnector starts one supervisor per configured endpoint; call it in
// a goroutine. It returns immediately when no endpoint is configured.
func RunReverseConnector() {
	RunReverseConnectorWith(utils.GCFG.ConnectEndpoints())
}

// RunReverseConnectorWith is the testable core of RunReverseConnector: it
// validates the endpoints and starts a supervisor for every usable one.
func RunReverseConnectorWith(endpoints []string) {
	valid, rejected, duplicated := utils.ParseConnectEndpoints(endpoints)
	for _, problem := range rejected {
		utils.DErrorf("MiaoSpeed Reverse | Skipping invalid endpoint, %s", problem)
	}
	// Duplicates are already reported by the CLI startup validation; keep this
	// defensive path quiet unless verbose logging is on.
	for _, duplicate := range duplicated {
		utils.DLogf("MiaoSpeed Reverse | Skipping duplicated endpoint, url=%s", duplicate)
	}
	if len(valid) == 0 {
		utils.DErrorf("MiaoSpeed Reverse | No usable endpoint to serve, reverse connector not started")
		return
	}

	utils.DWarnf("MiaoSpeed Reverse | Starting reverse connector, endpoints=%d pool=negotiated(default %d per endpoint)",
		len(valid), reverseDefaultPoolSize)
	for i, rawURL := range valid {
		label := reverseEndpointLabel(i, rawURL)
		utils.DWarnf("MiaoSpeed Reverse | [%s] endpoint registered, url=%s", label, rawURL)
		go runEndpointSupervisor(label, rawURL)
	}
}

// reverseEndpointLabel builds a short, stable log tag for an endpoint, e.g.
// "ep0(panel.example.com)". Full urls are too noisy to repeat on every line.
func reverseEndpointLabel(idx int, rawURL string) string {
	if target, err := url.Parse(rawURL); err == nil && target.Host != "" {
		return fmt.Sprintf("ep%d(%s)", idx, target.Host)
	}
	return fmt.Sprintf("ep%d", idx)
}

// runEndpointSupervisor owns one endpoint. It starts with a single probe
// connection and grows the pool when the client negotiates a bigger one through
// the ReverseAck. Growth is one-way on purpose: a later, smaller value is
// ignored so that healthy sessions are never torn down, which is also why
// workers never need a cancellation channel.
func runEndpointSupervisor(label string, rawURL string) {
	desired := reverseDefaultPoolSize
	negotiated := make(chan int, 8)

	for slot := 0; slot < desired; slot++ {
		go runReverseWorker(label, slot, rawURL, negotiated)
	}

	for want := range negotiated {
		want = clampReversePoolSize(want)
		if want <= desired {
			continue
		}
		for slot := desired; slot < want; slot++ {
			go runReverseWorker(label, slot, rawURL, negotiated)
		}
		utils.DWarnf("MiaoSpeed Reverse | [%s] pool scaled up to %d by client ack", label, want)
		desired = want
	}
}

// clampReversePoolSize keeps a client negotiated pool inside sane bounds so a
// broken or hostile ack cannot spawn an unbounded number of connections.
func clampReversePoolSize(size int) int {
	switch {
	case size < 1:
		return reverseDefaultPoolSize
	case size > reversePoolHardMax:
		return reversePoolHardMax
	default:
		return size
	}
}

// runReverseWorker owns one pool slot of one endpoint: dial, handshake, serve,
// then retry with exponential backoff. A graceful client close frees the slot on
// purpose, so reconnect immediately without backoff. The negotiated pool is
// reported to the supervisor as soon as the handshake completes, which owns the
// pool size decision.
func runReverseWorker(label string, slot int, rawURL string, negotiated chan<- int) {
	onAck := func(ack *interfaces.ReverseAck) {
		if ack.Pool <= 0 {
			return
		}
		// Never block the session on the supervisor.
		select {
		case negotiated <- ack.Pool:
		default:
		}
	}

	backoff := reverseBackoffBase
	for {
		started := time.Now()
		err := runReverseSession(label, slot, rawURL, onAck)
		if errors.Is(err, errClientClosed) {
			backoff = reverseBackoffBase
			continue
		}
		if time.Since(started) >= reverseStableLink {
			backoff = reverseBackoffBase
		}
		utils.DErrorf("MiaoSpeed Reverse | [%s] Slot %d connection lost, error=%s retry_in=%s", label, slot, err.Error(), backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > reverseBackoffMax {
			backoff = reverseBackoffMax
		}
	}
}

// errClientClosed marks a session the client ended deliberately.
var errClientClosed = errors.New("closed by client")

func isClientCloseError(err error) bool {
	if err == nil {
		return false
	}
	return websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
		websocket.CloseNoStatusReceived,
	)
}

// runReverseSession dials the client, performs the msr-v1 handshake and
// then serves the standard miaospeed protocol until the connection dies. onAck
// is called right after the handshake completes, because the session itself may
// stay alive for hours and the caller must not wait for it to end before acting
// on the negotiated values.
func runReverseSession(label string, slot int, rawURL string, onAck func(*interfaces.ReverseAck)) error {
	conn, resp, err := reverseDialer.Dial(rawURL, http.Header{})
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close() // gorilla leaves the body open on non-101 responses
			return fmt.Errorf("dial failed with http status %d", resp.StatusCode)
		}
		return fmt.Errorf("dial failed: %w", err)
	}
	remote := conn.RemoteAddr().String()
	utils.DLogf("MiaoSpeed Reverse | [%s] Slot %d connected, remote=%s", label, slot, remote)

	ack, err := reverseHandshake(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}
	if onAck != nil {
		onAck(ack)
	}

	heartbeat := int64(reverseHeartbeatSecs)
	if ack.Heartbeat > 0 {
		heartbeat = ack.Heartbeat
		if heartbeat < reverseHeartbeatMinSecs {
			heartbeat = reverseHeartbeatMinSecs
		}
		if heartbeat > reverseHeartbeatMaxSecs {
			heartbeat = reverseHeartbeatMaxSecs
		}
	}
	interval := time.Duration(heartbeat) * time.Second
	readWindow := 2 * interval

	utils.DWarnf("MiaoSpeed Reverse | [%s] Slot %d link established, remote=%s client=%s/%s session=%s heartbeat=%ds maxTasks=%d pool=%d",
		label, slot, remote, ack.Name, ack.Version, ack.SessionID, heartbeat, ack.MaxTasks, ack.Pool)

	// The read deadline is renewed by pongs, so a dead link surfaces within
	// two heartbeat intervals even when TCP does not notice.
	_ = conn.SetReadDeadline(time.Now().Add(readWindow))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readWindow))
	})

	done := make(chan struct{})
	defer close(done)
	go reverseHeartbeatLoop(conn, interval, done)

	sessionErr := handleWsSession(conn, remote)
	if isClientCloseError(sessionErr) {
		utils.DLogf("MiaoSpeed Reverse | [%s] Slot %d closed by client, redialing immediately", label, slot)
		return errClientClosed
	}
	if sessionErr != nil {
		return fmt.Errorf("session closed: %w", sessionErr)
	}
	return errClientClosed
}

// reverseHandshake sends the ReverseHello and validates the ReverseAck.
func reverseHandshake(conn *websocket.Conn) (*interfaces.ReverseAck, error) {
	nonce := utils.RandomUUID()
	ts := time.Now().Unix()
	hello := &interfaces.ReverseHello{
		Type:      interfaces.ReverseMsgHello,
		Protocol:  interfaces.ReverseProtocolV1,
		Version:   utils.VERSION,
		Nonce:     nonce,
		Timestamp: ts,
		Sign:      reverseHandshakeSign(utils.GCFG.Token, nonce, ts),
	}
	// Bound the handshake write; cleared below so it cannot leak into the session.
	_ = conn.SetWriteDeadline(time.Now().Add(reverseDialTimeout))
	if err := conn.WriteJSON(hello); err != nil {
		return nil, fmt.Errorf("handshake write failed: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	_ = conn.SetReadDeadline(time.Now().Add(2 * reverseDialTimeout))
	var ack interfaces.ReverseAck
	if err := conn.ReadJSON(&ack); err != nil {
		return nil, fmt.Errorf("handshake read failed: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{}) // hand over to the session without deadlines

	if ack.Type != interfaces.ReverseMsgAck {
		reason := ack.Error
		if reason == "" {
			reason = "unknown reason"
		}
		return nil, fmt.Errorf("handshake rejected by client: %s", reason)
	}
	if ack.Protocol != interfaces.ReverseProtocolV1 {
		return nil, fmt.Errorf("handshake protocol mismatch, backend=%s client=%s", interfaces.ReverseProtocolV1, ack.Protocol)
	}
	if ack.Sign != utils.SignChallenge(utils.GCFG.Token, hello.Sign) {
		return nil, fmt.Errorf("handshake signature mismatch, check the token on both sides")
	}
	return &ack, nil
}

// reverseHeartbeatLoop pings the client on the negotiated interval.
// WriteControl is safe alongside session data writes and carries its own
// deadline, so a stalled link cannot hang it.
func reverseHeartbeatLoop(conn *websocket.Conn, interval time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(interval)); err != nil {
				_ = conn.Close()
				return
			}
		}
	}
}
