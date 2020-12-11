package ulid

import (
	"testing"
)

func TestUlid(t *testing.T) {
	ctx := NewContext()
	id := ctx.Ulid()
	if len(id) != 26 {
		t.Errorf("Expected ulid length to be == 26, not %d", len(id))
	}
}
