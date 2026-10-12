package audit_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/plexusone/keyforge/audit"
)

func TestRecorder(t *testing.T) {
	r := &audit.Recorder{}
	for _, a := range []audit.Action{audit.KeyCreated, audit.KeyActivated} {
		if err := r.Emit(context.Background(), audit.Event{Action: a, Outcome: audit.Success}); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.Actions(); !reflect.DeepEqual(got, []audit.Action{audit.KeyCreated, audit.KeyActivated}) {
		t.Fatalf("Actions = %v", got)
	}
	ev := r.Events()
	ev[0].Action = "changed"
	if r.Events()[0].Action != audit.KeyCreated {
		t.Fatal("Events returns the recorder's own slice")
	}
}

func TestRecorderCanFail(t *testing.T) {
	boom := errors.New("sink down")
	r := &audit.Recorder{Err: boom}
	if err := r.Emit(context.Background(), audit.Event{}); !errors.Is(err, boom) {
		t.Fatalf("Emit = %v", err)
	}
	if len(r.Events()) != 0 {
		t.Fatal("a failed emit was recorded")
	}
}

func TestNotRecorded(t *testing.T) {
	if audit.NotRecorded(nil) != nil {
		t.Fatal("NotRecorded(nil) is not nil")
	}
	boom := errors.New("sink down")
	err := audit.NotRecorded(boom)
	if !errors.Is(err, audit.ErrNotRecorded) || !errors.Is(err, boom) {
		t.Fatalf("NotRecorded = %v, want both the sentinel and the cause", err)
	}
}

func TestActorContext(t *testing.T) {
	ctx := context.Background()
	if audit.ActorFrom(ctx) != "" {
		t.Fatal("an actor appeared from nowhere")
	}
	if got := audit.ActorFrom(audit.WithActor(ctx, "alice")); got != "alice" {
		t.Fatalf("ActorFrom = %q", got)
	}
}

func TestDiscard(t *testing.T) {
	if err := audit.Discard.Emit(context.Background(), audit.Event{}); err != nil {
		t.Fatal(err)
	}
}

// TestActionNamesMatchTheSpecification pins the wire names of the actions.
func TestActionNamesMatchTheSpecification(t *testing.T) {
	want := map[audit.Action]string{
		audit.KeyCreated: "key.created", audit.KeyRotated: "key.rotated", audit.KeyActivated: "key.activated",
		audit.KeyRolledBack: "key.rolled_back", audit.KeyRetireRequested: "key.retire_requested",
		audit.KeyRetireCancelled: "key.retire_cancelled", audit.KeyRetired: "key.retired",
		audit.KeyDestroyed: "key.destroyed", audit.KeyCompromised: "key.compromised",
		audit.WrapFailed: "wrap.failed", audit.AdminRead: "admin.read", audit.GuardDenied: "guard.denied",
		audit.GuardPending: "guard.pending", audit.JobFailed: "job.failed", audit.BackupStale: "backup.stale",
		audit.SubjectShredRequest: "subject.shred_requested", audit.SubjectShredComplete: "subject.shred_completed",
	}
	for a, name := range want {
		if string(a) != name {
			t.Errorf("%q != %q", a, name)
		}
		if !strings.Contains(name, ".") {
			t.Errorf("%q has no namespace", name)
		}
	}
}
