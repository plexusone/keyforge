// Package metrics defines the small interface through which keyforge reports
// rates, failures and overdue keys, and the names it reports them under.
//
// The core knows nothing of any metrics system: it calls a [Metrics], which
// defaults to discarding. An adapter to Prometheus or OpenTelemetry is a few
// lines over this interface and belongs in the host or in a separate module, so
// that the core takes no dependency on either.
//
// Labels are bounded by construction: the purpose is a configured name, and an
// outcome or reason is one of a small fixed set. A subject, a key identifier or
// an error message is never a label.
package metrics

import (
	"sync"
	"time"
)

// Label is one dimension of a metric.
type Label struct {
	Key, Value string
}

// L returns a label.
func L(key, value string) Label { return Label{Key: key, Value: value} }

// Metrics receives measurements. It must be safe for concurrent use and must not
// block: it is called on the data path.
type Metrics interface {
	// Count adds delta to a monotonically increasing counter.
	Count(name string, delta int64, labels ...Label)
	// Gauge sets a value that can go up and down.
	Gauge(name string, value float64, labels ...Label)
	// Observe records a duration, for a histogram or a summary.
	Observe(name string, d time.Duration, labels ...Label)
}

type discard struct{}

func (discard) Count(string, int64, ...Label)           {}
func (discard) Gauge(string, float64, ...Label)         {}
func (discard) Observe(string, time.Duration, ...Label) {}

// Discard is a Metrics that drops every measurement.
var Discard Metrics = discard{}

// Names of the metrics keyforge reports, in the Prometheus convention.
const (
	// Operations is the count of data-path operations, labelled op, purpose and
	// outcome.
	Operations = "keyforge_operations_total"
	// OperationDuration is how long they took, labelled op and purpose.
	OperationDuration = "keyforge_operation_duration"
	// CacheLookups counts unwrapped-key cache lookups, labelled cache and
	// result (hit or miss).
	CacheLookups = "keyforge_cache_lookups_total"
	// EpochAdvances counts new data key epochs, labelled purpose and reason
	// (first, cap, age, not_active, manual).
	EpochAdvances = "keyforge_epoch_advances_total"
	// Rotations counts KEK rotations, labelled purpose and outcome.
	Rotations = "keyforge_kek_rotations_total"
	// RewrappedKeys counts data keys moved to a new KEK version, labelled
	// outcome (moved, skipped, failed).
	RewrappedKeys = "keyforge_rewrapped_keys_total"
	// RotationOverdue is how many seconds a KEK rotation is past due, labelled
	// purpose. It is zero when nothing is overdue.
	RotationOverdue = "keyforge_kek_rotation_overdue_seconds"
	// JobsStarted counts jobs the scheduler started, labelled kind.
	JobsStarted = "keyforge_jobs_started_total"
	// JobsFailed counts jobs that failed, labelled kind.
	JobsFailed = "keyforge_jobs_failed_total"
	// JobsWaiting is how many due jobs a tick held back, a gauge.
	JobsWaiting = "keyforge_jobs_waiting"
	// JobsInFlight is how many due jobs already had a run, a gauge.
	JobsInFlight = "keyforge_jobs_in_flight"
)

// Outcomes of an operation.
const (
	OutcomeOK             = "ok"
	OutcomeUnavailable    = "unavailable"
	OutcomeUnusable       = "unusable"
	OutcomeAuthentication = "authentication"
	OutcomeInvalid        = "invalid"
	OutcomeRefused        = "refused"
	OutcomeShredded       = "shredded"
	OutcomeError          = "error"
)

// Recorder is a Metrics that keeps what it was given, for tests and examples.
type Recorder struct {
	mu       sync.Mutex
	counts   map[string]int64
	gauges   map[string]float64
	observed map[string][]time.Duration
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder {
	return &Recorder{counts: map[string]int64{}, gauges: map[string]float64{}, observed: map[string][]time.Duration{}}
}

// key renders a metric name and its labels into one stable string, with labels
// in the order given.
func key(name string, labels []Label) string {
	if len(labels) == 0 {
		return name
	}
	b := []byte(name)
	b = append(b, '{')
	for i, l := range labels {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, l.Key...)
		b = append(b, '=')
		b = append(b, l.Value...)
	}
	return string(append(b, '}'))
}

// Count implements [Metrics].
func (r *Recorder) Count(name string, delta int64, labels ...Label) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[key(name, labels)] += delta
}

// Gauge implements [Metrics].
func (r *Recorder) Gauge(name string, value float64, labels ...Label) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[key(name, labels)] = value
}

// Observe implements [Metrics].
func (r *Recorder) Observe(name string, d time.Duration, labels ...Label) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := key(name, labels)
	r.observed[k] = append(r.observed[k], d)
}

// Counter returns a counter's value, with labels in the order they were
// reported. An unreported counter is zero.
func (r *Recorder) Counter(name string, labels ...Label) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[key(name, labels)]
}

// GaugeValue returns a gauge's last value and whether it was ever set.
func (r *Recorder) GaugeValue(name string, labels ...Label) (float64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.gauges[key(name, labels)]
	return v, ok
}

// Observations returns how many durations were observed.
func (r *Recorder) Observations(name string, labels ...Label) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.observed[key(name, labels)])
}

// Names returns every counter and gauge name and label set that was reported,
// so a test can check that no label carries something unbounded.
func (r *Recorder) Names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for k := range r.counts {
		out = append(out, k)
	}
	for k := range r.gauges {
		out = append(out, k)
	}
	for k := range r.observed {
		out = append(out, k)
	}
	return out
}
