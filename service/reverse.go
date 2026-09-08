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

// The reverse connector keeps a fixed-size pool of outbound websocket
// connections to the client/panel (see `-connect`). Every pooled connection
// is a complete, independent miaospeed session speaking the same protocol as
// the inbound listener; a single connection already multiplexes any number
// of concurrent tasks. Lost connections are replaced in the background with
// exponential backoff (1s..60s) so the pool size is eventually restored.

const (
	reversePoolSize      = 4
	reverseHeartbeatSecs = 30
	reverseDialTimeout   = 15 * time.Second
	reverseBackoffBase   = 1 * time.Second
	reverseBackoffMax    = 60 * time.Second

	// reverseStableLink is the uptime after which a link counts as healthy;
	// its loss restarts the backoff curve from the base delay instead of
	// growing it further.
	reverseStableLink = 30 * time.Second
)

var reverseDialer = websocket.Dialer{
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
	HandshakeTimeout: reverseDialTimeout,
}

// reverseHandshakeSign builds the handshake signature:
// hashMiaoSpeed(token, "reverse-hello|nonce|timestamp"). The panel must
// implement the same algorithm (see README reverse-connection section).
func reverseHandshakeSign(token, nonce string, timestamp int64) string {
	return utils.SignChallenge(token, fmt.Sprintf("reverse-hello|%s|%d", nonce, timestamp))
}

// RunReverseConnector starts maintaining the outbound connection pool; call
// it in a goroutine. It exits early if the connect URL is empty or invalid.
func RunReverseConnector() {
	rawURL := utils.GCFG.ConnectURL
	if rawURL == "" {
		return
	}

	target, err := url.Parse(rawURL)
	if err != nil {
		utils.DErrorf("MiaoSpeed Reverse | Invalid connect url, url=%s error=%s", rawURL, err.Error())
		return
	}
	switch target.Scheme {
	case "ws", "wss":
	default:
		utils.DErrorf("MiaoSpeed Reverse | Connect url scheme must be ws or wss, url=%s", rawURL)
		return
	}
	if target.Host == "" {
		utils.DErrorf("MiaoSpeed Reverse | Connect url is missing a host, url=%s", rawURL)
		return
	}

	utils.DWarnf("MiaoSpeed Reverse | Starting reverse connector, url=%s pool=%d", rawURL, reversePoolSize)
	for i := 0; i < reversePoolSize; i++ {
		go runReverseWorker(i, rawURL)
	}
}

// runReverseWorker owns one pool slot: dial, handshake, serve the session,
// and on any failure retry with exponential backoff. A graceful close by the
// client (normal closure / going away) means a task finished and the client
// freed the slot on purpose, so reconnect immediately without backoff.
func runReverseWorker(slot int, rawURL string) {
	backoff := reverseBackoffBase
	for {
		started := time.Now()
		err := runReverseSession(slot, rawURL)
		if errors.Is(err, errClientClosed) {
			backoff = reverseBackoffBase
			continue
		}
		if time.Since(started) >= reverseStableLink {
			// The link was healthy for a while, so the client is probably
			// fine and this was a fluke: restart the backoff curve.
			backoff = reverseBackoffBase
		}
		if err == nil {
			backoff = reverseBackoffBase
			continue
		}
		utils.DErrorf("MiaoSpeed Reverse | Slot %d connection lost, error=%s retry_in=%s", slot, err.Error(), backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > reverseBackoffMax {
			backoff = reverseBackoffMax
		}
	}
}

// errClientClosed marks a session the client ended deliberately (normal
// close handshake after a finished task, or a stop request).
var errClientClosed = errors.New("closed by client")

// isClientCloseError reports whether the websocket close was initiated by
// the client with an expected close code, rather than a network failure.
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

// runReverseSession dials the client, performs the reverse-v1 handshake and
// then serves the standard miaospeed protocol until the connection dies.
func runReverseSession(slot int, rawURL string) error {
	conn, resp, err := reverseDialer.Dial(rawURL, http.Header{})
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial failed with http status %d", resp.StatusCode)
		}
		return fmt.Errorf("dial failed: %w", err)
	}
	remote := conn.RemoteAddr().String()
	utils.DLogf("MiaoSpeed Reverse | Slot %d connected, remote=%s", slot, remote)

	ack, err := reverseHandshake(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}

	heartbeat := int64(reverseHeartbeatSecs)
	if ack.Heartbeat > 0 {
		heartbeat = ack.Heartbeat
	}
	interval := time.Duration(heartbeat) * time.Second
	readWindow := 2 * interval

	utils.DWarnf("MiaoSpeed Reverse | Slot %d link established, remote=%s client=%s/%s session=%s heartbeat=%ds maxTasks=%d",
		slot, remote, ack.Name, ack.Version, ack.SessionID, heartbeat, ack.MaxTasks)

	// Liveness: the read deadline is renewed by incoming pongs, so a
	// silently dead link is detected within two heartbeat intervals even
	// when TCP itself does not notice.
	_ = conn.SetReadDeadline(time.Now().Add(readWindow))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readWindow))
	})

	done := make(chan struct{})
	defer close(done)
	go reverseHeartbeatLoop(conn, interval, done)

	sessionErr := handleWsSession(conn, remote)
	if isClientCloseError(sessionErr) {
		utils.DLogf("MiaoSpeed Reverse | Slot %d closed by client, redialing immediately", slot)
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
	if err := conn.WriteJSON(hello); err != nil {
		return nil, fmt.Errorf("handshake write failed: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * reverseDialTimeout))
	var ack interfaces.ReverseAck
	if err := conn.ReadJSON(&ack); err != nil {
		return nil, fmt.Errorf("handshake read failed: %w", err)
	}
	// Hand the connection over to the session without inherited deadlines.
	_ = conn.SetReadDeadline(time.Time{})

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
// WriteControl is safe to call concurrently with the session's data writes
// and carries its own deadline, so a stalled link unblocks the heartbeat
// instead of hanging forever.
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
