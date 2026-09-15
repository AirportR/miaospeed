package preconfigs

import (
	"embed"
)

// tlsEmbedFS carries every TLS certificate pair that is compiled into the binary.

//go:embed embeded/tls
var tlsEmbedFS embed.FS

//go:embed embeded/ca-certificates.crt
var MIAOKO_ROOT_CA []byte
