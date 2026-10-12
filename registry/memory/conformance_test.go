package memory

import (
	"context"
	"testing"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/registry/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func() registry.Store { return NewStore() })
}

// recorder is a storetest.TB that records failures instead of failing a test.
type recorder struct{ failed bool }

type abort struct{}

func (r *recorder) Helper()                   {}
func (r *recorder) Logf(string, ...any)       {}
func (r *recorder) Errorf(string, ...any)     { r.failed = true }
func (r *recorder) Fatalf(f string, a ...any) { r.Errorf(f, a...); panic(abort{}) }

// failing runs every case against a store and returns the names that failed.
func failing(newStore func() registry.Store) map[string]bool {
	out := map[string]bool{}
	for _, c := range storetest.Cases() {
		rec := &recorder{}
		func() {
			defer func() {
				if v := recover(); v != nil {
					if _, ok := v.(abort); !ok {
						panic(v)
					}
				}
			}()
			c.Run(rec, newStore())
		}()
		if rec.failed {
			out[c.Name] = true
		}
	}
	return out
}

// TestSuiteCatchesDefects gives the suite a store with one defect at a time.
// Each must be caught by the case written for it, so a suite that has gone soft
// is noticed.
func TestSuiteCatchesDefects(t *testing.T) {
	t.Run("internal defects", func(t *testing.T) {
		tests := []struct {
			name string
			d    defect
			want string
		}{
			{"activation does not demote the previous version", defectNoDemote, "ActivationDemotesPrevious"},
			{"any decrypt-only version can be reactivated", defectAnyRollback, "RollbackOnlyToMostRecentDecryptOnly"},
			{"a referenced version can be retired", defectIgnoreReferences, "RetirementNeedsDelayAndNoReferences"},
			{"retirement ignores its delay", defectIgnoreDelay, "RetirementNeedsDelayAndNoReferences"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := failing(func() registry.Store { s := NewStore(); s.defect = tt.d; return s })
				if !got[tt.want] {
					t.Fatalf("case %s did not fail; failed: %v", tt.want, got)
				}
			})
		}
	})

	t.Run("boundary defects", func(t *testing.T) {
		tests := []struct {
			name string
			wrap func(registry.Store) registry.Store
			want string
		}{
			{"ignores the context", func(s registry.Store) registry.Store { return ignoresContext{s} }, "CancelledContextChangesNothing"},
			{"advance is not a compare-and-set", func(s registry.Store) registry.Store { return blindAdvance{s} }, "AdvanceDEK"},
			{"grants past the limit", func(s registry.Store) registry.Store { return overGrant{s} }, "ReserveEncryptions"},
			{"shares returned records", func(s registry.Store) registry.Store { return &sharesRecords{Store: s} }, "RecordsAreCopies"},
			{"ignores the cursor", func(s registry.Store) registry.Store { return ignoresCursor{s} }, "ListDEKsPagesInOrder"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := failing(func() registry.Store { return tt.wrap(NewStore()) })
				if !got[tt.want] {
					t.Fatalf("case %s did not fail; failed: %v", tt.want, got)
				}
			})
		}
	})
}

type ignoresContext struct{ registry.Store }

func (s ignoresContext) CreateKEK(_ context.Context, k registry.KEK) error {
	return s.Store.CreateKEK(context.Background(), k)
}

type blindAdvance struct{ registry.Store }

func (s blindAdvance) AdvanceDEK(ctx context.Context, p keyforge.Purpose, subject string, _ uint32, next keyforge.DEKRecord) (keyforge.DEKRecord, error) {
	from := uint32(0)
	if cur, err := s.Store.CurrentDEK(ctx, p, subject); err == nil {
		from = cur.Epoch // always "wins": the caller's view is ignored
		next.Epoch = from + 1
	}
	return s.Store.AdvanceDEK(ctx, p, subject, from, next)
}

type overGrant struct{ registry.Store }

func (s overGrant) ReserveEncryptions(ctx context.Context, id envelope.ID, n, limit uint64) (uint64, error) {
	return s.Store.ReserveEncryptions(ctx, id, n, limit*2)
}

type sharesRecords struct {
	registry.Store
	last map[envelope.ID]keyforge.DEKRecord
}

func (s *sharesRecords) GetDEK(ctx context.Context, id envelope.ID) (keyforge.DEKRecord, error) {
	if s.last == nil {
		s.last = map[envelope.ID]keyforge.DEKRecord{}
	}
	if rec, ok := s.last[id]; ok {
		return rec, nil // the same backing array every time
	}
	rec, err := s.Store.GetDEK(ctx, id)
	if err == nil {
		s.last[id] = rec
	}
	return rec, err
}

type ignoresCursor struct{ registry.Store }

func (s ignoresCursor) ListDEKs(ctx context.Context, f registry.DEKFilter) ([]keyforge.DEKRecord, error) {
	f.After = envelope.ID{}
	return s.Store.ListDEKs(ctx, f)
}
