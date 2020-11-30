package tunnel

import (
	"time"
)

// Now returns the current Unix time in milliseconds.
func Now() uint64 {
	return uint64(time.Now().UnixNano() / 1000000)
}
