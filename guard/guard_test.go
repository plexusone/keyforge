package guard_test

import (
	"context"
	"errors"
	"testing"

	"github.com/plexusone/keyforge/guard"
)

var bg = context.Background()

func fixed(d guard.Decision) guard.Guard {
	return guard.Func(func(context.Context, guard.Request) (guard.Decision, error) { return d, nil })
}

func TestAllCombinesAnswers(t *testing.T) {
	boom := errors.New("down")
	failing := guard.Func(func(context.Context, guard.Request) (guard.Decision, error) { return guard.Decision{}, boom })

	tests := []struct {
		name   string
		guards []guard.Guard
		want   guard.Outcome
		reason string
		err    error
	}{
		{"none denies", nil, guard.Denied, guard.ErrNoGuard, nil},
		{"all allow", []guard.Guard{guard.AllowAll(), guard.AllowAll()}, guard.Allowed, "", nil},
		{"one denies", []guard.Guard{guard.AllowAll(), guard.DenyAll("legal hold")}, guard.Denied, "legal hold", nil},
		{"deny beats pending", []guard.Guard{fixed(guard.AwaitApproval("ticket")), guard.DenyAll("hold")}, guard.Denied, "hold", nil},
		{"pending beats allow", []guard.Guard{guard.AllowAll(), fixed(guard.AwaitApproval("ticket 7"))}, guard.Pending, "ticket 7", nil},
		{"first pending is reported", []guard.Guard{fixed(guard.AwaitApproval("a")), fixed(guard.AwaitApproval("b"))}, guard.Pending, "a", nil},
		{"an error is an error", []guard.Guard{guard.AllowAll(), failing}, 0, "", boom},
		{"an invalid outcome is refused", []guard.Guard{fixed(guard.Decision{Outcome: 9})}, 0, "", guard.ErrBadDecision},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := guard.All(tt.guards...).Check(bg, guard.Request{})
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Fatalf("Check error = %v, want %v", err, tt.err)
				}
				return
			}
			if err != nil || d.Outcome != tt.want || d.Reason != tt.reason {
				t.Fatalf("Check = %+v, %v; want %v %q", d, err, tt.want, tt.reason)
			}
		})
	}
}

func TestOutcomeNames(t *testing.T) {
	for o, want := range map[guard.Outcome]string{guard.Allowed: "allowed", guard.Denied: "denied", guard.Pending: "pending"} {
		if o.String() != want {
			t.Errorf("%d = %q, want %q", o, o.String(), want)
		}
	}
	if guard.Outcome(0).String() == "" || guard.Outcome(0).String() == "allowed" {
		t.Error("the zero outcome reads as a real one")
	}
}

func TestZeroOutcomeIsNotAnAllow(t *testing.T) {
	var d guard.Decision
	if d.Outcome == guard.Allowed {
		t.Fatal("a zero Decision is an allow: a guard that forgets to answer would permit destruction")
	}
}
