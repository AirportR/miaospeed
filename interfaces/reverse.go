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
// Message field names follow the existing miaospeed convention (PascalCase,
// no JSON tags).

const ReverseProtocolV1 = "msr-v1"

const (
	ReverseMsgHello = "hello"
	ReverseMsgAck   = "ack"
	ReverseMsgError = "error"
)

// ReverseHello is the first message sent by miaospeed over a freshly
// dialed reverse connection.
type ReverseHello struct {
	Type      string // always "hello"
	Protocol  string // protocol version, see ReverseProtocolV1
	Version   string // miaospeed version
	Nonce     string // random string for the handshake signature
	Timestamp int64  // unix seconds
	Sign      string // hashMiaoSpeed(token, "reverse-hello|"+nonce+"|"+timestamp)
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
	Pool      int    // connections the backend should keep for this endpoint, 0 = backend default (1)
	Error     string // rejection reason when Type != "ack"
}
