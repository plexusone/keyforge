package metrics_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/keyforge/metrics"
)

func TestRecorderCountsGaugesAndObservations(t *testing.T) {
	r := metrics.NewRecorder()
	op := metrics.L("op", "encrypt")
	r.Count(metrics.Operations, 2, op, metrics.L("outcome", "ok"))
	r.Count(metrics.Operations, 3, op, metrics.L("outcome", "ok"))
	r.Count(metrics.Operations, 1, op, metrics.L("outcome", "unavailable"))
	if got := r.Counter(metrics.Operations, op, metrics.L("outcome", "ok")); got != 5 {
		t.Errorf("Counter = %d, want 5", got)
	}
	if got := r.Counter(metrics.Operations, op, metrics.L("outcome", "unavailable")); got != 1 {
		t.Errorf("Counter = %d, want 1", got)
	}
	if got := r.Counter(metrics.Operations); got != 0 {
		t.Errorf("an unlabelled counter that was never reported = %d", got)
	}

	if _, ok := r.GaugeValue(metrics.RotationOverdue); ok {
		t.Error("a gauge that was never set reports a value")
	}
	r.Gauge(metrics.RotationOverdue, 90, metrics.L("purpose", "orders"))
	r.Gauge(metrics.RotationOverdue, 0, metrics.L("purpose", "orders"))
	if v, ok := r.GaugeValue(metrics.RotationOverdue, metrics.L("purpose", "orders")); !ok || v != 0 {
		t.Errorf("GaugeValue = %v, %v, want the last value 0", v, ok)
	}

	r.Observe(metrics.OperationDuration, time.Millisecond, op)
	r.Observe(metrics.OperationDuration, 2*time.Millisecond, op)
	if got := r.Observations(metrics.OperationDuration, op); got != 2 {
		t.Errorf("Observations = %d, want 2", got)
	}
}

func TestDiscardIsSafe(t *testing.T) {
	m := metrics.Discard
	m.Count("x", 1, metrics.L("a", "b"))
	m.Gauge("x", 1)
	m.Observe("x", time.Second)
}

func TestMetricNamesAreStable(t *testing.T) {
	names := []string{
		metrics.Operations, metrics.OperationDuration, metrics.CacheLookups, metrics.EpochAdvances,
		metrics.Rotations, metrics.RewrappedKeys, metrics.RotationOverdue, metrics.JobsStarted,
		metrics.JobsFailed, metrics.JobsWaiting, metrics.JobsInFlight,
	}
	seen := map[string]bool{}
	for _, n := range names {
		if !strings.HasPrefix(n, "keyforge_") {
			t.Errorf("%q is not namespaced", n)
		}
		if seen[n] {
			t.Errorf("%q is used twice", n)
		}
		seen[n] = true
	}
	if !slices.Contains(names, "keyforge_kek_rotation_overdue_seconds") {
		t.Error("the overdue metric was renamed: dashboards and alerts depend on it")
	}
}
