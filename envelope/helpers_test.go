package envelope_test

import (
	"crypto/cipher"
	"testing"
)

// newExplicitNonceAEAD returns an AEAD that takes an explicit nonce, which the
// envelope must refuse. It skips the test when the process runs with
// GODEBUG=fips140=only, where cipher.NewGCM is not available.
func newExplicitNonceAEAD(t *testing.T, block cipher.Block) (aead cipher.AEAD) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Skipf("cipher.NewGCM is not available in this mode: %v", r)
		}
	}()
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Skipf("cipher.NewGCM is not available in this mode: %v", err)
	}
	return aead
}
