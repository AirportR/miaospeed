package service

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/utils"
	"github.com/gorilla/websocket"
)

// The reverse connector keeps a pool of outbound websocket connections to the
// client/panel (see `-connect`). Each session connection is an independent
// miaospeed session identical to the inbound listener; lost connections are
// re-dialed with exponential backoff.
//
// Several endpoints may be served at once. Every endpoint owns a supervisor
// goroutine and its own pool, so an endpoint that is unreachable only costs its
// own connections.
//
// The size of a pool is owned by the client:
//
//   - the first (probe) session connection is always dialed, and until a control
//     link takes over the Pool field of the ReverseAck sets a grow-only target;
//   - a client that advertises ReverseAck.Control also gets one dedicated control
//     connection per endpoint, over which ReverseScale frames resize the pool at
//     any time. Once that link is online the ack Pool stops driving the pool, so
//     a reconnecting session cannot undo a shrink the client asked for;
//   - while no control link is online the backend shrinks the pool on its own
//     once its connections have been idle for reverseIdleTimeout, down to a floor
//     of one connection.
//
// Autonomous shrinking is suspended whenever a control link is online, because
// the client owns the pool then. The two mechanisms never fight.
//
// Idleness is measured by the client ping. A client that wants its connections
// keeps pinging, including while it runs tasks, so a connection nobody pings is
// one nobody uses. A client that never pings is never shrunk on the backend's
// own initiative, which is what keeps clients predating this feature untouched.

const (
	// reverseDefaultPoolSize is the pool used until the client negotiates a
	// bigger one, and also the floor a shrinking pool never goes below.
	reverseDefaultPoolSize = 1
	// reversePoolHardMax caps what a client may negotiate, by ack or by
	// ReverseScale.
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

	// reverseControlWriteWait bounds the control frames the backend writes
	// outside of a session (pong replies and graceful closes).
	reverseControlWriteWait = 1 * time.Second

	// reverseScaleReplyTimeout bounds how long a control link waits for the
	// supervisor to apply one ReverseScale.
	reverseScaleReplyTimeout = 5 * time.Second
)

// reverseIdleTimeoutNs holds the autonomous shrink threshold in nanoseconds. It
// is atomic so tests can shorten it through SetReverseIdleTimeoutForTest.
var reverseIdleTimeoutNs atomic.Int64

func init() {
	reverseIdleTimeoutNs.Store(int64(5 * time.Minute))
}

// SetReverseIdleTimeoutForTest shortens the autonomous shrink threshold so
// cross-package tests do not have to wait for the production value. It returns
// the previous threshold so a test can put it back.
func SetReverseIdleTimeoutForTest(d time.Duration) time.Duration {
	return time.Duration(reverseIdleTimeoutNs.Swap(int64(d)))
}

func reverseIdleTimeout() time.Duration {
	return time.Duration(reverseIdleTimeoutNs.Load())
}

// reverseIdleCheckEvery derives the idle poll interval from the threshold, so a
// shortened test timeout also shortens the polling.
func reverseIdleCheckEvery() time.Duration {
	every := reverseIdleTimeout() / 10
	if every < 50*time.Millisecond {
		every = 50 * time.Millisecond
	}
	return every
}

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

// endpointPool is the pool state of one endpoint. The supervisor goroutine is
// its only writer; session workers read snapshots to decide whether they may
// retire themselves.
type endpointPool struct {
	mu            sync.Mutex
	desired       int
	controlOnline bool
	ackDrives     bool
	// retiring counts sessions that already committed to an autonomous
	// retirement but are still listed in the pool. The floor is checked against
	// desired-retiring, so two sessions that go idle at the same instant can
	// never both leave and drop the endpoint below one connection.
	retiring int
}

func newEndpointPool() *endpointPool {
	return &endpointPool{desired: reverseDefaultPoolSize, ackDrives: true}
}

func (p *endpointPool) setDesired(n int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.desired = n
}

func (p *endpointPool) setControlOnline(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.controlOnline = v
}

// stopAckDrivenGrowth freezes the grow-only ack Pool. It is called once the
// client takes over through a control link, and once the backend has shrunk the
// pool on its own: in both cases a static handshake value must no longer be able
// to undo that decision.
func (p *endpointPool) stopAckDrivenGrowth() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ackDrives = false
}

func (p *endpointPool) ackDrivesPool() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ackDrives
}

// reserveAutonomousRetirement reports whether an idle session of this endpoint
// may retire itself right now, and reserves the slot when it may. The floor is
// checked against the sessions that already reserved a retirement, so a burst of
// sessions going idle together can never take the endpoint below one connection.
// A control link being online vetoes it entirely, since the client owns the pool
// then.
func (p *endpointPool) reserveAutonomousRetirement() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.controlOnline || p.desired-p.retiring <= reverseDefaultPoolSize {
		return false
	}
	p.retiring++
	return true
}

// completeRetirement republishes the pool size after a slot left the list, and
// releases that slot's reservation when it retired on its own. Both happen under
// one lock, so an idle session checking the floor can never slip into the gap
// between releasing a reservation and shrinking desired.
func (p *endpointPool) completeRetirement(size int, autonomous bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if autonomous && p.retiring > 0 {
		p.retiring--
	}
	p.desired = size
}

// sessionActivity records the last sign of life on a session connection. The
// client ping is the only idle signal available: handleWsSession is shared with
// the inbound listener and must not be modified, so task activity cannot be
// observed directly.
type sessionActivity struct {
	lastNs atomic.Int64
	pinged atomic.Bool
}

// touch marks the connection as alive without claiming a client ping was seen.
func (a *sessionActivity) touch() {
	a.lastNs.Store(time.Now().UnixNano())
}

// mark records a client ping, which refreshes the idle window and proves the
// client is willing to report its own activity.
func (a *sessionActivity) mark() {
	a.touch()
	a.pinged.Store(true)
}

func (a *sessionActivity) idleFor() time.Duration {
	return time.Since(time.Unix(0, a.lastNs.Load()))
}

func (a *sessionActivity) sawPing() bool {
	return a.pinged.Load()
}

// retirement reports a session slot that left the pool for good.
type retirement struct {
	slot       *reverseSessionSlot
	autonomous bool // retired by the backend's idle shrink, not by the client
}

// scaleRequest asks the supervisor to apply a new pool size.
type scaleRequest struct {
	pool  int
	seq   int64
	reply chan int
}

// reverseSessionSlot is one session connection slot of an endpoint. It carries
// everything its worker needs, so the supervisor and the worker only exchange
// signals instead of sharing mutable state.
type reverseSessionSlot struct {
	label  string
	id     int
	rawURL string
	pool   *endpointPool

	// retire is signalled by the supervisor when this slot must go away. It is
	// buffered so the supervisor never blocks on a busy worker.
	retire chan struct{}
	// acked carries the ReverseAck of this slot, for the initial pool size and
	// the control support bit.
	acked chan<- *interfaces.ReverseAck
	// exited tells the supervisor this slot is gone for good. It is buffered for
	// reversePoolHardMax+2 entries, which is more than the pool can ever hold, so
	// a retiring worker is never blocked and its retirement is never dropped.
	exited chan<- retirement
}

func (s *reverseSessionSlot) name() string {
	return fmt.Sprintf("Slot %d", s.id)
}

// run owns this slot until the supervisor retires it. It never returns on its
// own: losing a link only schedules a redial.
func (s *reverseSessionSlot) run() {
	activity := &sessionActivity{}
	onAck := func(ack *interfaces.ReverseAck) {
		select {
		case s.acked <- ack:
		default:
		}
	}

	err := reverseRetryLoop(s.label, s.name(), func() error {
		return runReverseSession(s, activity, onAck)
	}, s.retire)

	select {
	case s.exited <- retirement{slot: s, autonomous: errors.Is(err, errSlotRetiredAutonomous)}:
	default:
		utils.DErrorf("MiaoSpeed Reverse | [%s] %s retirement could not be reported", s.label, s.name())
	}
}

// runEndpointSupervisor owns one endpoint. It keeps the pool at the size the
// client asked for, spawns and retires session workers accordingly, and is the
// only writer of the shared pool state.
func runEndpointSupervisor(label string, rawURL string) {
	pool := newEndpointPool()

	acked := make(chan *interfaces.ReverseAck, 8)
	exited := make(chan retirement, reversePoolHardMax+2)
	scaleReq := make(chan scaleRequest, 8)
	controlUp := make(chan bool, 8)

	var slots []*reverseSessionSlot
	nextID := 0
	controlStarted := false

	spawn := func() {
		slot := &reverseSessionSlot{
			label:  label,
			id:     nextID,
			rawURL: rawURL,
			pool:   pool,
			retire: make(chan struct{}, 1),
			acked:  acked,
			exited: exited,
		}
		nextID++
		slots = append(slots, slot)
		go slot.run()
	}

	// growTo and shrinkTo keep the slot list and the shared desired count in
	// sync. A retire signal only asks a worker to go away: the slot is dropped
	// right away so a worker that is still busy finishing a task is never
	// counted twice and never gets a second signal.
	growTo := func(target int) {
		for len(slots) < target {
			spawn()
		}
		pool.setDesired(len(slots))
	}
	shrinkTo := func(target int) {
		for len(slots) > target {
			victim := slots[len(slots)-1]
			slots = slots[:len(slots)-1]
			select {
			case victim.retire <- struct{}{}:
			default: // already asked to retire
			}
		}
		pool.setDesired(len(slots))
	}

	growTo(reverseDefaultPoolSize)

	for {
		select {
		case ack := <-acked:
			if !controlStarted && ack.Control {
				controlStarted = true
				utils.DWarnf("MiaoSpeed Reverse | [%s] client declared control support, starting control link", label)
				go runControlLink(label, rawURL, scaleReq, controlUp)
			}
			if !pool.ackDrivesPool() {
				continue
			}
			if want := clampReversePoolSize(ack.Pool); want > len(slots) {
				utils.DWarnf("MiaoSpeed Reverse | [%s] pool scaled up to %d by client ack", label, want)
				growTo(want)
			}

		case r := <-exited:
			for i, s := range slots {
				if s == r.slot {
					slots = append(slots[:i], slots[i+1:]...)
					break
				}
			}
			if r.autonomous {
				// The backend retired this connection on its own, so the ack
				// Pool must stop driving the pool: otherwise the next
				// reconnecting session would grow it straight back.
				pool.stopAckDrivenGrowth()
			}
			pool.completeRetirement(len(slots), r.autonomous)
			utils.DWarnf("MiaoSpeed Reverse | [%s] pool is now %d (autonomous=%v)", label, len(slots), r.autonomous)

		case req := <-scaleReq:
			target := clampReversePoolSize(req.pool)
			if target > len(slots) {
				growTo(target)
			} else {
				shrinkTo(target)
			}
			utils.DWarnf("MiaoSpeed Reverse | [%s] pool set to %d by control request (requested=%d seq=%d)",
				label, len(slots), req.pool, req.seq)
			select {
			case req.reply <- len(slots):
			default:
			}

		case up := <-controlUp:
			pool.setControlOnline(up)
			if up {
				pool.stopAckDrivenGrowth()
				utils.DWarnf("MiaoSpeed Reverse | [%s] control link online, autonomous shrink suspended", label)
			} else {
				utils.DWarnf("MiaoSpeed Reverse | [%s] control link offline, autonomous shrink resumed", label)
			}
		}
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

// runControlLink keeps at most one control connection alive for an endpoint and
// relays ReverseScale requests to the supervisor. It is only started for
// endpoints whose client advertised control support, and it is never part of the
// pool, so it is never retired.
func runControlLink(label, rawURL string, scale chan<- scaleRequest, online chan<- bool) {
	never := make(chan struct{})
	reverseRetryLoop(label, "Control", func() error {
		return runControlSession(label, rawURL, scale, online)
	}, never)
}

// runControlSession serves a dedicated control connection: no tasks, only
// ReverseScale frames in and ReverseScaleAck frames out.
func runControlSession(label, rawURL string, scale chan<- scaleRequest, online chan<- bool) error {
	conn, remote, err := dialReverse(rawURL)
	if err != nil {
		return err
	}

	ack, err := reverseHandshake(conn, interfaces.ReverseRoleControl)
	if err != nil {
		_ = conn.Close()
		return err
	}
	heartbeat, interval, readWindow := reverseHeartbeat(ack)
	utils.DWarnf("MiaoSpeed Reverse | [%s] Control link established, remote=%s client=%s/%s session=%s heartbeat=%ds",
		label, remote, ack.Name, ack.Version, ack.SessionID, heartbeat)

	reverseSetupKeepalive(conn, readWindow)

	done := make(chan struct{})
	defer close(done)
	go reverseHeartbeatLoop(conn, interval, done)
	defer conn.Close()

	notify := func(up bool) {
		select {
		case online <- up:
		default:
		}
	}
	notify(true)
	defer notify(false)

	for {
		var msg interfaces.ReverseScale
		if err := conn.ReadJSON(&msg); err != nil {
			return fmt.Errorf("control read failed: %w", err)
		}
		if msg.Type != interfaces.ReverseMsgScale {
			utils.DWarnf("MiaoSpeed Reverse | [%s] Control link ignored unsupported message type=%q", label, msg.Type)
			continue
		}

		applied, err := applyScale(scale, msg.Pool, msg.Seq)
		reply := &interfaces.ReverseScaleAck{
			Type: interfaces.ReverseMsgScale,
			Seq:  msg.Seq,
			Pool: applied,
		}
		if err != nil {
			reply.Error = err.Error()
		}
		if werr := conn.WriteJSON(reply); werr != nil {
			return fmt.Errorf("control ack write failed: %w", werr)
		}
		utils.DWarnf("MiaoSpeed Reverse | [%s] Control link applied pool=%d (requested=%d seq=%d)",
			label, applied, msg.Pool, msg.Seq)
	}
}

// applyScale hands a ReverseScale to the supervisor and waits for the applied value.
func applyScale(scale chan<- scaleRequest, pool int, seq int64) (int, error) {
	req := scaleRequest{pool: pool, seq: seq, reply: make(chan int, 1)}
	select {
	case scale <- req:
	case <-time.After(reverseScaleReplyTimeout):
		return 0, errors.New("backend is busy, retry later")
	}
	select {
	case applied := <-req.reply:
		return applied, nil
	case <-time.After(reverseScaleReplyTimeout):
		return 0, errors.New("backend did not apply the scale in time")
	}
}

// dialReverse dials one reverse endpoint and returns the connection
func dialReverse(rawURL string) (*websocket.Conn, string, error) {
	conn, resp, err := reverseDialer.Dial(rawURL, http.Header{})
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close() // gorilla leaves the body open on non-101 responses
			return nil, "", fmt.Errorf("dial failed with http status %d", resp.StatusCode)
		}
		return nil, "", fmt.Errorf("dial failed: %w", err)
	}
	return conn, conn.RemoteAddr().String(), nil
}

// reverseHeartbeat resolves the keepalive settings the client asked for.
func reverseHeartbeat(ack *interfaces.ReverseAck) (secs int64, interval, readWindow time.Duration) {
	secs = int64(reverseHeartbeatSecs)
	if ack.Heartbeat > 0 {
		secs = ack.Heartbeat
		if secs < reverseHeartbeatMinSecs {
			secs = reverseHeartbeatMinSecs
		}
		if secs > reverseHeartbeatMaxSecs {
			secs = reverseHeartbeatMaxSecs
		}
	}
	interval = time.Duration(secs) * time.Second
	return secs, interval, 2 * interval
}

// reverseSetupKeepalive arms the read deadline renewal shared by session
func reverseSetupKeepalive(conn *websocket.Conn, readWindow time.Duration) {
	_ = conn.SetReadDeadline(time.Now().Add(readWindow))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(readWindow))
	})
}

// runReverseSession dials the client, performs the msr-v1 handshake and then
// serves the standard miaospeed protocol until the connection dies.
func runReverseSession(slot *reverseSessionSlot, activity *sessionActivity, onAck func(*interfaces.ReverseAck)) error {
	conn, remote, err := dialReverse(slot.rawURL)
	if err != nil {
		return err
	}
	utils.DLogf("MiaoSpeed Reverse | [%s] %s connected, remote=%s", slot.label, slot.name(), remote)

	ack, err := reverseHandshake(conn, "")
	if err != nil {
		_ = conn.Close()
		return err
	}
	if onAck != nil {
		onAck(ack)
	}

	heartbeat, interval, readWindow := reverseHeartbeat(ack)
	utils.DWarnf("MiaoSpeed Reverse | [%s] %s link established, remote=%s client=%s/%s session=%s heartbeat=%ds maxTasks=%d pool=%d",
		slot.label, slot.name(), remote, ack.Name, ack.Version, ack.SessionID, heartbeat, ack.MaxTasks, ack.Pool)

	reverseSetupKeepalive(conn, readWindow)
	activity.touch()

	conn.SetPingHandler(func(appData string) error {
		activity.mark()
		return writePong(conn, appData)
	})

	stopIdle := make(chan struct{})
	retireReason := make(chan bool, 1)
	defer close(stopIdle)
	go watchIdle(slot, conn, activity, stopIdle, retireReason)

	done := make(chan struct{})
	defer close(done)
	go reverseHeartbeatLoop(conn, interval, done)

	sessionErr := handleWsSession(conn, remote)

	select {
	case autonomous := <-retireReason:
		if autonomous {
			return errSlotRetiredAutonomous
		}
		return errSlotRetired
	default:
	}

	if isClientCloseError(sessionErr) {
		utils.DLogf("MiaoSpeed Reverse | [%s] %s closed by client, redialing immediately", slot.label, slot.name())
		return errClientClosed
	}
	if sessionErr != nil {
		return fmt.Errorf("session closed: %w", sessionErr)
	}
	return errClientClosed
}

// writePong answers a client ping.
func writePong(conn *websocket.Conn, appData string) error {
	err := conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(reverseControlWriteWait))
	if errors.Is(err, websocket.ErrCloseSent) {
		return nil
	}
	return err
}

// watchIdle retires this session once it looks idle.
func watchIdle(slot *reverseSessionSlot, conn *websocket.Conn, activity *sessionActivity, stop <-chan struct{}, reason chan<- bool) {
	ticker := time.NewTicker(reverseIdleCheckEvery())
	defer ticker.Stop()

	requested := false
	for {
		select {
		case <-stop:
			return
		case <-slot.retire:
			requested = true
		case <-ticker.C:
		}

		if activity.idleFor() < reverseIdleTimeout() {
			continue
		}
		autonomous := false
		if !requested {
			if !activity.sawPing() || !slot.pool.reserveAutonomousRetirement() {
				continue
			}
			autonomous = true
		}

		utils.DWarnf("MiaoSpeed Reverse | [%s] %s idle for %s, retiring (autonomous=%v)",
			slot.label, slot.name(), reverseIdleTimeout(), autonomous)
		select {
		case reason <- autonomous:
		default:
		}
		closeGracefully(conn)
		return
	}
}

// closeGracefully closes a reverse link with a normal close code so the client
// sees a deliberate retirement instead of a broken connection.
func closeGracefully(conn *websocket.Conn) {
	_ = conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "idle"),
		time.Now().Add(reverseControlWriteWait))
	_ = conn.Close()
}

// reverseRetryLoop drives one reverse link until it is retired
func reverseRetryLoop(label, what string, serve func() error, retire <-chan struct{}) error {
	backoff := reverseBackoffBase
	for {
		started := time.Now()
		err := serve()
		if errors.Is(err, errSlotRetired) {
			utils.DLogf("MiaoSpeed Reverse | [%s] %s retired", label, what)
			return err
		}
		if errors.Is(err, errClientClosed) {
			backoff = reverseBackoffBase
			continue
		}
		if time.Since(started) >= reverseStableLink {
			backoff = reverseBackoffBase
		}
		utils.DErrorf("MiaoSpeed Reverse | [%s] %s connection lost, error=%s retry_in=%s", label, what, err.Error(), backoff)
		select {
		case <-retire:
			utils.DLogf("MiaoSpeed Reverse | [%s] %s retired while backing off", label, what)
			return errSlotRetired
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > reverseBackoffMax {
			backoff = reverseBackoffMax
		}
	}
}

var errClientClosed = errors.New("closed by client")
var errSlotRetired = errors.New("slot retired")
var errSlotRetiredAutonomous = fmt.Errorf("%w: idle shrink", errSlotRetired)

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

// reverseHandshake sends the ReverseHello and validates the ReverseAck.
func reverseHandshake(conn *websocket.Conn, role string) (*interfaces.ReverseAck, error) {
	nonce := utils.RandomUUID()
	ts := time.Now().Unix()
	hello := &interfaces.ReverseHello{
		Type:      interfaces.ReverseMsgHello,
		Protocol:  interfaces.ReverseProtocolV1,
		Version:   utils.VERSION,
		Nonce:     nonce,
		Timestamp: ts,
		Sign:      reverseHandshakeSign(utils.GCFG.Token, nonce, ts),
		Role:      role,
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
