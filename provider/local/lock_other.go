//go:build !windows && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package local

import (
	"context"
	"errors"
)

// lockFile is not supported on this platform. The provider fails closed
// rather than write a keyring that another process could interleave with.
func lockFile(context.Context, string) (func(), error) {
	return nil, errors.New("local: advisory file locking is not supported on this platform")
}

func syncDir(string) error { return nil }
