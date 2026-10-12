//go:build windows

package local

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileExclusiveLock   = 0x2
	lockfileFailImmediately = 0x1
	errorLockViolation      = syscall.Errno(33)
)

// lockFile takes an exclusive advisory lock on path, creating it if needed, and
// returns the function that releases it. It polls so that a cancelled context
// stops the wait.
func lockFile(ctx context.Context, path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("local: opening lock file: %w", err)
	}
	h := syscall.Handle(f.Fd())
	for {
		var ol syscall.Overlapped
		r, _, e := procLockFileEx.Call(uintptr(h), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
		if r != 0 {
			return func() {
				var ol syscall.Overlapped
				_, _, _ = procUnlockFileEx.Call(uintptr(h), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
				_ = f.Close() //nolint:errcheck // closing a lock file; the lock is released with the handle
			}, nil
		}
		if !errors.Is(e, errorLockViolation) {
			_ = f.Close() //nolint:errcheck // the lock error is the one to report
			return nil, fmt.Errorf("local: locking the keyring: %w", e)
		}
		select {
		case <-ctx.Done():
			_ = f.Close() //nolint:errcheck // the context error is the one to report
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// syncDir is a no-op on Windows, where a directory cannot be opened for
// flushing; the rename itself is atomic.
func syncDir(string) error { return nil }
