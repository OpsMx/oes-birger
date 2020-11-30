package ulid

import (
	"math/rand"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/skandragon/grpc-bidir/tunnel"
)

// Context holds the state needed to generate a ULID using random values.
// Not thread safe.
type Context struct {
	entropy *ulid.MonotonicEntropy
}

// NewContext returns the context needed for subsequent calls.
func NewContext() *Context {
	t := time.Unix(1000000, 0)
	entropy := ulid.Monotonic(rand.New(rand.NewSource(t.UnixNano())), 0)
	return &Context{entropy: entropy}
}

// Ulid - return a new ULID as a string.
func Ulid(context *Context) string {
	return ulid.MustNew(tunnel.Now(), context.entropy).String()
}
