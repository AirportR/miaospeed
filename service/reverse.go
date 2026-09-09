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
// connections to the client/panel (see `-connect`). Each connection is an
// independent miaospeed session identical to the inbound listener; lost
// connections are re-dialed with exponential backoff.

const (
	reversePoolSize      = 4
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

// RunReverseConnector maintains the outbound connection pool; call it in a
// goroutine. It exits early if the connect URL is empty or invalid.
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

// runReverseWorker owns one pool slot: dial, handshake, serve, then retry
// with exponential backoff. A graceful client close frees the slot on
// purpose, so reconnect immediately without backoff.
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
			backoff = reverseBackoffBase
		}
		utils.DErrorf("MiaoSpeed Reverse | Slot %d connection lost, error=%s retry_in=%s", slot, err.Error(), backoff)
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
// then serves the standard miaospeed protocol until the connection dies.
func runReverseSession(slot int, rawURL string) error {
	conn, resp, err := reverseDialer.Dial(rawURL, http.Header{})
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close() // gorilla leaves the body open on non-101 responses
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
		if heartbeat < reverseHeartbeatMinSecs {
			heartbeat = reverseHeartbeatMinSecs
		}
		if heartbeat > reverseHeartbeatMaxSecs {
			heartbeat = reverseHeartbeatMaxSecs
		}
	}
	interval := time.Duration(heartbeat) * time.Second
	readWindow := 2 * interval

	utils.DWarnf("MiaoSpeed Reverse | Slot %d link established, remote=%s client=%s/%s session=%s heartbeat=%ds maxTasks=%d",
		slot, remote, ack.Name, ack.Version, ack.SessionID, heartbeat, ack.MaxTasks)

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
