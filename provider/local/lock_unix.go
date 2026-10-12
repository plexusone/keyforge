//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// lockFile takes an exclusive advisory lock on path, creating it if needed, and
// returns the function that releases it. It polls so that a cancelled context
// stops the wait.
func lockFile(ctx context.Context, path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("local: opening lock file: %w", err)
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // G115: a file descriptor fits an int
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:gosec,errcheck // G115: a descriptor fits an int; the close below releases the lock regardless
				_ = f.Close()                                   //nolint:errcheck // closing a lock file; the lock is released by the kernel with the descriptor
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close() //nolint:errcheck // the lock error is the one to report
			return nil, fmt.Errorf("local: locking the keyring: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close() //nolint:errcheck // the context error is the one to report
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// syncDir flushes a directory so that a rename within it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close() //nolint:errcheck // the sync error is the one to report
		return err
	}
	return d.Close()
}
