package ulid

import (
	"math/rand"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/opsmx/grpc-bidir/pkg/tunnel"
)

// Context holds the state needed to generate a ULID using random values.  This
// is a locked structure, so should not be used by a lot of threads if IDs are
// generated at a high rate.
type Context struct {
	sync.Mutex
	entropy *ulid.MonotonicEntropy
}

// NewContext returns the context needed for subsequent calls.
func NewContext() *Context {
	t := time.Unix(1000000, 0)
	entropy := ulid.Monotonic(rand.New(rand.NewSource(t.UnixNano())), 0)
	return &Context{entropy: entropy}
}

// Ulid - return a new ULID as a string.
func (ctx *Context) Ulid() string {
	ctx.Lock()
	defer ctx.Unlock()
	return ulid.MustNew(tunnel.Now(), ctx.entropy).String()
}
