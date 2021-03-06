package ulid

import (
	cryptorand "crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// Context holds the state needed to generate a ULID using random values.  This
// is a locked structure, so should not be used by a lot of threads if IDs are
// generated at a high rate.
type Context struct {
	entropy *ulid.MonotonicEntropy
}

// NewContext returns the context needed for subsequent calls.
func NewContext() *Context {
	entropy := ulid.Monotonic(cryptorand.Reader, 0)
	return &Context{entropy: entropy}
}

// Ulid - return a new ULID as a string.
func (ctx *Context) Ulid() string {
	t := time.Now().Unix()
	return ulid.MustNew(uint64(t), ctx.entropy).String()
}
