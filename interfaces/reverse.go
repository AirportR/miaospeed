package interfaces

// Reverse connection protocol (msr-v1).
//
// When miaospeed runs with `-connect <url>` it dials OUT to a websocket
// endpoint hosted by the client/panel (useful when the miaospeed host is
// behind NAT and the panel has a public address). `-connect` may be given
// more than once (or comma separated) to serve several endpoints at the same
// time; every endpoint keeps its own pool of connections and its own
// reconnect backoff. After the websocket is established, miaospeed sends a
// ReverseHello and waits for a ReverseAck; once the ack is accepted, the
// connection speaks the exact same SlaveRequest/SlaveResponse protocol as the
// inbound server mode, with roles unchanged (the client still sends requests,
// miaospeed still computes and streams results).
//
// Resizing a pool (the policy lives in service/reverse.go):
//
//   - a client that sets ReverseAck.Control also gets one dedicated control
//     connection per endpoint. Its ReverseHello carries Role "control", it
//     never carries a task, and it is never part of the pool;
//   - the client then sends ReverseScale over that link to ask for a pool size,
//     in either direction, and miaospeed answers ReverseScaleAck with the size
//     it really applied. Both frames share the "scale" type, so a reader has to
//     know which direction it is looking at;
//   - Seq is per control connection and is a correlation id only: the client
//     numbers its own requests and miaospeed echoes the number back without
//     ever deduping on it. A control link that reconnects starts over at zero,
//     which is safe because the previous link's replies cannot reach it.

const ReverseProtocolV1 = "msr-v1"

const (
	ReverseMsgHello = "hello"
	ReverseMsgAck   = "ack"
	ReverseMsgError = "error"
	ReverseMsgScale = "scale"
)

// ReverseRoleControl is the ReverseHello.Role of a control connection. A plain
// task session sends no role at all, so an empty Role means "session".
const ReverseRoleControl = "control"

// ReverseHello is the first message sent by miaospeed over a freshly
// dialed reverse connection.
type ReverseHello struct {
	Type      string // always "hello"
	Protocol  string // protocol version, see ReverseProtocolV1
	Version   string // miaospeed version
	Nonce     string // random string for the handshake signature
	Timestamp int64  // unix seconds
	Sign      string // hashMiaoSpeed(token, "reverse-hello|"+nonce+"|"+timestamp)
	Role      string `json:"Role,omitempty"` // "control" = control link; never part of Sign
}

// ReverseAck is the client's reply to a ReverseHello. Type "ack" completes
// the handshake; anything else is a rejection and miaospeed drops the
// connection and retries with backoff.
type ReverseAck struct {
	Type      string // "ack" or "error"
	Protocol  string // echo the negotiated protocol version
	Sign      string // hashMiaoSpeed(token, hello.Sign), proves the client holds the same token
	Version   string // client/panel version, for logs
	Name      string // client/panel name (e.g. "koipy"), for logs
	Timestamp int64  // client unix seconds, for clock skew inspection
	SessionID string // session id assigned by the client to this pooled connection, for log correlation
	Heartbeat int64  // requested ping/pong interval in seconds, 0 = backend default (30s)
	MaxTasks  int    // suggested max concurrent tasks per connection, 0 = unlimited; logged only
	Pool      int    // initial connections for this endpoint, 0 = backend default (1); drives growth only, and stops mattering once a control link is online
	Control   bool   // client understands Role "control" and serves control links; false for clients that predate the feature
	Error     string // rejection reason when Type != "ack"
}

// ReverseScale is sent by the client over a control connection to ask for a new
// pool size for that endpoint.
type ReverseScale struct {
	Type string // "scale"
	Pool int    // desired connections for this endpoint
	Seq  int64  // per control connection, echoed back in ReverseScaleAck.Seq
}

// ReverseScaleAck reports the outcome of one ReverseScale. It shares the "scale"
// type with the request, so it is only ever read on the control link.
type ReverseScaleAck struct {
	Type  string // "scale"
	Seq   int64  // echo of ReverseScale.Seq
	Pool  int    // value actually applied after clamping
	Error string // non-empty when the request was rejected
}
