package memory_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/algorithm"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider"
	"github.com/plexusone/keyforge/registry/memory"
)

var bg = context.Background()

func id(seed byte) envelope.ID {
	var i envelope.ID
	for n := range i {
		i[n] = seed + byte(n)
	}
	return i
}

func newStore(t *testing.T) (*memory.Store, keyforge.KEKVersion) {
	t.Helper()
	s := memory.NewStore()
	ref := provider.KeyRef{ID: id(0xA0), Provider: "p", ProviderRef: "ref"}
	if err := s.PutKEK(ref); err != nil {
		t.Fatal(err)
	}
	kv := keyforge.KEKVersion{Ref: ref, Version: 1}
	if err := s.SetActiveKEK("orders", kv); err != nil {
		t.Fatal(err)
	}
	return s, kv
}

func record(seed byte, epoch uint32, kv keyforge.KEKVersion) keyforge.DEKRecord {
	return keyforge.DEKRecord{
		ID: id(seed), Purpose: "orders", Epoch: epoch, Algorithm: algorithm.AES256GCM,
		KEKID: kv.Ref.ID, KEKVersion: kv.Version, Wrapped: []byte{1, 2, 3}, State: keyforge.DEKActive,
	}
}

func TestKEKLookups(t *testing.T) {
	s, kv := newStore(t)
	got, err := s.ActiveKEK(bg, "orders")
	if err != nil || got != kv {
		t.Fatalf("ActiveKEK = %+v, %v", got, err)
	}
	if _, err := s.ActiveKEK(bg, "unknown"); !errors.Is(err, keyforge.ErrNoActiveKEK) {
		t.Fatalf("ActiveKEK for an unknown purpose = %v", err)
	}
	if ref, err := s.KEK(bg, kv.Ref.ID); err != nil || ref != kv.Ref {
		t.Fatalf("KEK = %+v, %v", ref, err)
	}
	if _, err := s.KEK(bg, id(1)); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Fatalf("KEK for an unknown ID = %v", err)
	}
	if err := s.SetActiveKEK("orders", keyforge.KEKVersion{Ref: provider.KeyRef{ID: id(9), Provider: "p", ProviderRef: "r"}, Version: 1}); !errors.Is(err, keyforge.ErrKEKNotFound) {
		t.Fatalf("SetActiveKEK with an unregistered KEK = %v", err)
	}
}

func TestAdvanceDEKIsCompareAndSet(t *testing.T) {
	s, kv := newStore(t)

	first, err := s.AdvanceDEK(bg, "orders", "", 0, record(1, 1, kv))
	if err != nil || first.ID != id(1) {
		t.Fatalf("first AdvanceDEK = %+v, %v", first, err)
	}
	cur, err := s.CurrentDEK(bg, "orders", "")
	if err != nil || cur.ID != id(1) {
		t.Fatalf("CurrentDEK = %+v, %v", cur, err)
	}

	// A second writer that also saw "no key" loses and gets the winner back.
	loser, err := s.AdvanceDEK(bg, "orders", "", 0, record(2, 1, kv))
	if err != nil || loser.ID != id(1) {
		t.Fatalf("losing AdvanceDEK = %+v, %v, want the winner's record", loser, err)
	}
	if _, err := s.GetDEK(bg, id(2)); !errors.Is(err, keyforge.ErrDEKNotFound) {
		t.Fatal("the losing record was stored")
	}

	second, err := s.AdvanceDEK(bg, "orders", "", 1, record(3, 2, kv))
	if err != nil || second.ID != id(3) {
		t.Fatalf("AdvanceDEK from epoch 1 = %+v, %v", second, err)
	}
	prev, err := s.GetDEK(bg, id(1))
	if err != nil || prev.State != keyforge.DEKDecryptOnly {
		t.Fatalf("the previous key = %+v, %v, want decrypt-only", prev, err)
	}
}

func TestAdvanceDEKValidates(t *testing.T) {
	s, kv := newStore(t)
	bad := []struct {
		name string
		rec  keyforge.DEKRecord
		from uint32
	}{
		{"wrong epoch", record(1, 5, kv), 0},
		{"wrong purpose", func() keyforge.DEKRecord { r := record(1, 1, kv); r.Purpose = "other"; return r }(), 0},
		{"zero id", func() keyforge.DEKRecord { r := record(1, 1, kv); r.ID = envelope.ID{}; return r }(), 0},
		{"unknown KEK", func() keyforge.DEKRecord { r := record(1, 1, kv); r.KEKID = id(0x77); return r }(), 0},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.AdvanceDEK(bg, "orders", "", tt.from, tt.rec); err == nil {
				t.Fatal("AdvanceDEK accepted the record")
			}
		})
	}
	if _, err := s.AdvanceDEK(bg, "orders", "", 3, record(1, 4, kv)); err == nil {
		t.Fatal("AdvanceDEK advanced from an epoch that does not exist")
	}
}

func TestReserveEncryptions(t *testing.T) {
	s, kv := newStore(t)
	rec := record(1, 1, kv)
	if _, err := s.AdvanceDEK(bg, "orders", "", 0, rec); err != nil {
		t.Fatal(err)
	}

	steps := []struct{ n, limit, want uint64 }{
		{4, 10, 4},
		{4, 10, 4},
		{4, 10, 2}, // the last block is partial: never past the limit
		{4, 10, 0},
		{4, 10, 0},
	}
	for i, st := range steps {
		got, err := s.ReserveEncryptions(bg, rec.ID, st.n, st.limit)
		if err != nil || got != st.want {
			t.Fatalf("step %d: granted %d, %v, want %d", i, got, err, st.want)
		}
	}
	if r, _ := s.GetDEK(bg, rec.ID); r.Reserved != 10 {
		t.Fatalf("Reserved = %d, want 10", r.Reserved)
	}

	// A key that is no longer current is granted nothing, which tells the
	// caller to advance.
	if _, err := s.AdvanceDEK(bg, "orders", "", 1, record(2, 2, kv)); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ReserveEncryptions(bg, rec.ID, 4, 100); err != nil || got != 0 {
		t.Fatalf("a replaced key was granted %d, %v", got, err)
	}
	if _, err := s.ReserveEncryptions(bg, id(0x66), 1, 10); !errors.Is(err, keyforge.ErrDEKNotFound) {
		t.Fatalf("reserve on an unknown key = %v", err)
	}
}

// TestReserveIsNeverOverGranted hammers one key from many goroutines and checks
// the total granted equals the limit exactly, which is what makes the cap hold
// across replicas.
func TestReserveIsNeverOverGranted(t *testing.T) {
	s, kv := newStore(t)
	rec := record(1, 1, kv)
	if _, err := s.AdvanceDEK(bg, "orders", "", 0, rec); err != nil {
		t.Fatal(err)
	}
	const limit = 1000
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		total uint64
	)
	for range 16 {
		wg.Go(func() {
			for {
				n, err := s.ReserveEncryptions(bg, rec.ID, 7, limit)
				if err != nil {
					t.Error(err)
					return
				}
				if n == 0 {
					return
				}
				mu.Lock()
				total += n
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if total != limit {
		t.Fatalf("granted %d in total, want exactly %d", total, limit)
	}
}

func TestRecordsAreCopies(t *testing.T) {
	s, kv := newStore(t)
	rec := record(1, 1, kv)
	if _, err := s.AdvanceDEK(bg, "orders", "", 0, rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDEK(bg, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	got.Wrapped[0] = 0xFF
	again, err := s.GetDEK(bg, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Wrapped, []byte{1, 2, 3}) {
		t.Fatal("a returned record shares its wrapped key with the store")
	}
}

func TestDEKsListing(t *testing.T) {
	s, kv := newStore(t)
	if _, err := s.AdvanceDEK(bg, "orders", "", 0, record(1, 1, kv)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdvanceDEK(bg, "orders", "", 1, record(2, 2, kv)); err != nil {
		t.Fatal(err)
	}
	list := s.DEKs()
	if len(list) != 2 || list[0].Epoch != 1 || list[1].Epoch != 2 {
		t.Fatalf("DEKs = %+v, want epochs 1 then 2", list)
	}
}

func TestCancelledContext(t *testing.T) {
	s, kv := newStore(t)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := s.ActiveKEK(ctx, "orders"); !errors.Is(err, context.Canceled) {
		t.Fatalf("ActiveKEK = %v", err)
	}
	if _, err := s.AdvanceDEK(ctx, "orders", "", 0, record(1, 1, kv)); !errors.Is(err, context.Canceled) {
		t.Fatalf("AdvanceDEK = %v", err)
	}
	if _, err := s.CurrentDEK(bg, "orders", ""); !errors.Is(err, keyforge.ErrDEKNotFound) {
		t.Fatal("a cancelled AdvanceDEK changed state")
	}
}
