// Package service is the HTTP control plane: an [http.Handler] for status, key
// listing, rotation, retirement, destruction, backup acknowledgement and the
// emergency procedures.
//
// It is a thin adapter over the library. Every handler calls the same
// operations a program would call directly, and holds no logic of its own.
//
// # What the host supplies
//
// Authentication and mounting are the host's. The host mounts the handler under
// its own router, authenticates the caller in its own middleware, names them
// with [audit.WithActor] so that the events a request causes are attributed, and
// supplies an [Authorizer] that is asked before every action. There is no
// default: a service with no authorizer cannot be constructed, so it is never
// open by omission.
//
// # What it will not reveal
//
// An action is authorized before the resource is looked up, so a caller who may
// not rotate a purpose cannot tell from the response whether the purpose
// exists. Responses carry identifiers, states, counts and times, and never key
// material, wrapped keys or plaintext. An unexpected failure is reported with a
// code and a generic message, and the detail is the host's to log.
package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/guard"
	"github.com/plexusone/keyforge/registry"
	"github.com/plexusone/keyforge/rotate"
	"github.com/plexusone/keyforge/status"
)

// Action names something a caller may be allowed to do.
type Action string

// Actions.
const (
	ActionStatus         Action = "status.read"
	ActionKeysList       Action = "keys.list"
	ActionRotate         Action = "keys.rotate"
	ActionRollback       Action = "keys.rollback"
	ActionRewrap         Action = "keys.rewrap"
	ActionRetireRequest  Action = "keys.retire.request"
	ActionRetireComplete Action = "keys.retire.complete"
	ActionRetireCancel   Action = "keys.retire.cancel"
	ActionDestroy        Action = "keys.destroy"
	ActionCompromiseKEK  Action = "keys.compromise"
	ActionCompromiseDEK  Action = "datakeys.compromise"
	ActionDestroyDEK     Action = "datakeys.destroy"
	ActionVerify         Action = "keys.verify"
	ActionBackupAck      Action = "backup.ack"
	ActionShredRequest   Action = "shred.request"
	ActionShredRead      Action = "shred.read"
)

// Authorizer decides whether the caller may perform an action. The caller's
// identity is whatever the host's middleware put on the context.
//
// purpose is the purpose the action concerns, or empty for an action that is
// not about one purpose. Return nil to allow, [ErrUnauthenticated] if there is
// no usable identity, or any other error to forbid.
type Authorizer interface {
	Authorize(ctx context.Context, action Action, purpose string) error
}

// AuthorizerFunc adapts a function to an [Authorizer].
type AuthorizerFunc func(ctx context.Context, action Action, purpose string) error

// Authorize implements [Authorizer].
func (f AuthorizerFunc) Authorize(ctx context.Context, action Action, purpose string) error {
	return f(ctx, action, purpose)
}

// ErrUnauthenticated is returned by an Authorizer when there is no identity. The
// service answers 401 for it and 403 for any other refusal.
var ErrUnauthenticated = errors.New("service: unauthenticated")

// Verifier checks that the keys a purpose depends on can be used now.
type Verifier interface {
	Verify(ctx context.Context, purposes ...keyforge.Purpose) []keyforge.VerifyResult
}

// BackupAcker records a backup acknowledgement for a provider's keyring. The
// local provider implements it.
type BackupAcker interface {
	AckBackup(ctx context.Context, generation uint64, at time.Time, note string) error
}

// MaxBodyBytes bounds a request body.
const MaxBodyBytes = 1 << 20

// Options configures a [Service].
type Options struct {
	// Store is the registry. Required.
	Store registry.Store
	// Rotator performs the operations. Required.
	Rotator *rotate.Rotator
	// Reporter builds status. Required.
	Reporter *status.Reporter
	// Authorizer is asked before every action. Required.
	Authorizer Authorizer
	// Verifier round-trips a test value through each purpose's keys. A
	// [keyforge.Client] satisfies it. Without one the verify endpoint is not
	// offered.
	Verifier Verifier
	// Backups acknowledges backups by provider name.
	Backups map[string]BackupAcker
	// Audit receives an event for each administrative read. The default
	// discards them.
	Audit audit.Sink
	// Clock defaults to the system clock.
	Clock keyforge.Clock
}

// Service is the HTTP control plane.
type Service struct {
	o   Options
	mux *http.ServeMux
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// New returns a service. It fails if there is no authorizer.
func New(o Options) (*Service, error) {
	switch {
	case o.Store == nil:
		return nil, errors.New("service: Options.Store is required")
	case o.Rotator == nil:
		return nil, errors.New("service: Options.Rotator is required")
	case o.Reporter == nil:
		return nil, errors.New("service: Options.Reporter is required")
	case o.Authorizer == nil:
		return nil, errors.New("service: Options.Authorizer is required: the control plane is never open by default")
	}
	if o.Audit == nil {
		o.Audit = audit.Discard
	}
	if o.Clock == nil {
		o.Clock = systemClock{}
	}
	s := &Service{o: o, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

// ServeHTTP implements [http.Handler].
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Service) routes() {
	h := s.mux.HandleFunc
	h("GET /v1/status", s.getStatus)
	h("GET /v1/health", s.getHealth)
	h("GET /v1/purposes", s.listPurposes)
	h("GET /v1/purposes/{purpose}", s.getPurpose)
	h("POST /v1/purposes/{purpose}/rotate", s.rotate)
	h("POST /v1/purposes/{purpose}/rollback", s.rollback)
	h("POST /v1/purposes/{purpose}/rewrap", s.rewrap)
	h("POST /v1/purposes/{purpose}/subjects/{subject}/shred", s.shred)
	h("GET /v1/purposes/{purpose}/subjects/{subject}/shred", s.shredStatus)
	h("POST /v1/keks/{kek}/versions/{version}/retire", s.requestRetire)
	h("POST /v1/keks/{kek}/versions/{version}/retire/complete", s.completeRetire)
	h("POST /v1/keks/{kek}/versions/{version}/retire/cancel", s.cancelRetire)
	h("POST /v1/keks/{kek}/versions/{version}/destroy", s.destroy)
	h("POST /v1/keks/{kek}/versions/{version}/compromise", s.compromiseKEK)
	h("POST /v1/datakeys/{id}/compromise", s.compromiseDEK)
	h("POST /v1/datakeys/{id}/destroy", s.destroyDEK)
	h("POST /v1/verify", s.verify)
	h("POST /v1/backups/{provider}/ack", s.ackBackup)
}

// ---- responses ----

// ErrorBody is the shape of every error response.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail is a stable code and a message that names no key material.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v) //nolint:errcheck // the status line is already sent; a broken connection has no one left to tell
}

func writeError(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, ErrorBody{Error: ErrorDetail{Code: errCode, Message: msg}})
}

// fail maps an error from the library onto a status and a code. The message of
// an unexpected error is replaced by a generic one: the detail is the host's to
// log, and nothing from a provider or a store is passed to a caller verbatim.
func fail(w http.ResponseWriter, err error) {
	type rule struct {
		is   error
		code int
		name string
	}
	rules := []rule{
		{keyforge.ErrKEKNotFound, http.StatusNotFound, "not_found"},
		{keyforge.ErrDEKNotFound, http.StatusNotFound, "not_found"},
		{registry.ErrVersionNotFound, http.StatusNotFound, "not_found"},
		{registry.ErrShredNotFound, http.StatusNotFound, "not_found"},
		{keyforge.ErrInvalidSubject, http.StatusBadRequest, "invalid_request"},
		{registry.ErrInvalid, http.StatusBadRequest, "invalid_request"},
		{registry.ErrInvalidTransition, http.StatusConflict, "invalid_state"},
		{rotate.ErrWrongState, http.StatusConflict, "invalid_state"},
		{rotate.ErrNotEligible, http.StatusConflict, "not_eligible"},
		{registry.ErrRetireDelay, http.StatusConflict, "retire_delay"},
		{registry.ErrVersionReferenced, http.StatusConflict, "version_referenced"},
		{registry.ErrNoRollbackTarget, http.StatusConflict, "no_rollback_target"},
		{registry.ErrConflict, http.StatusConflict, "conflict"},
		{rotate.ErrBackupStale, http.StatusConflict, "backup_stale"},
		{rotate.ErrBackupUnknown, http.StatusConflict, "backup_unknown"},
		{rotate.ErrNothingToRewrap, http.StatusConflict, "nothing_to_rewrap"},
		{rotate.ErrEmergencyIncomplete, http.StatusConflict, "emergency_incomplete"},
		{rotate.ErrNoEpochAdvancer, http.StatusServiceUnavailable, "not_configured"},
		{keyforge.ErrNoActiveKEK, http.StatusConflict, "no_active_key"},
		{keyforge.ErrKeyUnavailable, http.StatusServiceUnavailable, "unavailable"},
		{context.DeadlineExceeded, http.StatusGatewayTimeout, "timeout"},
		{context.Canceled, http.StatusServiceUnavailable, "cancelled"},
	}
	for _, r := range rules {
		if errors.Is(err, r.is) {
			writeError(w, r.code, r.name, r.is.Error())
			return
		}
	}
	writeError(w, http.StatusInternalServerError, "internal", "the operation failed")
}

// withWarning returns a response that carries a warning when the change was made
// but its audit event was not recorded: the caller must not be told it failed.
type result struct {
	Warnings []string `json:"warnings,omitempty"`
}

func warn(err error) result {
	if errors.Is(err, audit.ErrNotRecorded) {
		return result{Warnings: []string{"the change was made but its audit event was not recorded"}}
	}
	return result{}
}

// ok reports whether err is nil or only an audit gap.
func ok(err error) bool { return err == nil || errors.Is(err, audit.ErrNotRecorded) }

// ---- request plumbing ----

// authorize asks the authorizer and writes the refusal if there is one.
func (s *Service) authorize(w http.ResponseWriter, r *http.Request, a Action, purpose string) bool {
	err := s.o.Authorizer.Authorize(r.Context(), a, purpose)
	switch {
	case err == nil:
		return true
	case errors.Is(err, ErrUnauthenticated):
		writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required")
	default:
		writeError(w, http.StatusForbidden, "forbidden", "not permitted")
	}
	return false
}

func (s *Service) emitRead(r *http.Request, what, purpose string) {
	_ = s.o.Audit.Emit(r.Context(), audit.Event{ //nolint:errcheck // a read is not refused because its event could not be recorded
		ID: fmt.Sprintf("%d", s.o.Clock.Now().UnixNano()), Time: s.o.Clock.Now(), Actor: audit.ActorFrom(r.Context()),
		Action: audit.AdminRead, Purpose: purpose, Outcome: audit.Success, Reason: what,
	})
}

// decode reads an optional JSON body into v: absent is fine, unknown fields and
// anything over the limit are not. It is called only after the action has been
// authorized, so an unauthorized caller cannot make the service read a body.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the request body is too large")
		return false
	}
	if len(b) == 0 {
		return true
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "the body must be application/json")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the request body is not valid for this operation")
		return false
	}
	return true
}

func parseKEK(w http.ResponseWriter, v string) (envelope.ID, bool) {
	var id envelope.ID
	raw, err := hex.DecodeString(v)
	if err != nil || len(raw) != len(id) {
		writeError(w, http.StatusBadRequest, "invalid_request", "the key identifier is not 32 hex digits")
		return id, false
	}
	copy(id[:], raw)
	return id, true
}

func parseVersion(w http.ResponseWriter, v string) (uint32, bool) {
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || n == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "the version is not a positive integer")
		return 0, false
	}
	return uint32(n), true
}

// kekPurpose resolves a KEK to its purpose for authorization. An unknown KEK
// gives an empty purpose and found=false: the caller authorizes the action
// against no purpose first, and answers not-found only if that is allowed.
func (s *Service) kekPurpose(ctx context.Context, id envelope.ID) (purpose string, found bool) {
	k, err := s.o.Store.GetKEK(ctx, id)
	if err != nil {
		return "", false
	}
	return string(k.Purpose), true
}

// guarded runs a KEK-scoped action: parse, resolve the purpose, authorize, then
// call run.
func (s *Service) guarded(w http.ResponseWriter, r *http.Request, a Action, run func(id envelope.ID, version uint32)) {
	id, ok := parseKEK(w, r.PathValue("kek"))
	if !ok {
		return
	}
	version, ok := parseVersion(w, r.PathValue("version"))
	if !ok {
		return
	}
	purpose, found := s.kekPurpose(r.Context(), id)
	if !s.authorize(w, r, a, purpose) {
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", keyforge.ErrKEKNotFound.Error())
		return
	}
	run(id, version)
}

// ---- handlers ----

func (s *Service) getStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, ActionStatus, "") {
		return
	}
	s.emitRead(r, "status", "")
	writeJSON(w, http.StatusOK, s.o.Reporter.Report(r.Context()))
}

// getHealth answers 200 when the report is healthy and 503 with the problems
// when it is not, for a monitor or a load balancer that reads only the status.
func (s *Service) getHealth(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, ActionStatus, "") {
		return
	}
	rep := s.o.Reporter.Report(r.Context())
	code := http.StatusOK
	if !rep.Healthy {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"healthy": rep.Healthy, "problems": rep.Problems})
}

func (s *Service) listPurposes(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, ActionKeysList, "") {
		return
	}
	s.emitRead(r, "list purposes", "")
	writeJSON(w, http.StatusOK, map[string]any{"purposes": s.o.Reporter.Report(r.Context()).Purposes})
}

func (s *Service) getPurpose(w http.ResponseWriter, r *http.Request) {
	purpose := r.PathValue("purpose")
	if !s.authorize(w, r, ActionKeysList, purpose) {
		return
	}
	p := s.o.Reporter.Purpose(r.Context(), keyforge.Purpose(purpose))
	if p.Error != "" && p.ActiveVersion == 0 && len(p.Versions) == 0 {
		writeError(w, http.StatusNotFound, "not_found", "no such purpose")
		return
	}
	s.emitRead(r, "read purpose", purpose)
	writeJSON(w, http.StatusOK, p)
}

type rotateResponse struct {
	result
	KEKID string    `json:"kekId"`
	From  uint32    `json:"from"`
	To    uint32    `json:"to"`
	At    time.Time `json:"at"`
}

func (s *Service) rotate(w http.ResponseWriter, r *http.Request) {
	purpose := r.PathValue("purpose")
	if !s.authorize(w, r, ActionRotate, purpose) {
		return
	}
	res, err := s.o.Rotator.RotateKEK(r.Context(), keyforge.Purpose(purpose))
	if !ok(err) {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rotateResponse{result: warn(err), KEKID: res.KEK.ID.String(), From: res.From, To: res.To, At: res.At})
}

func (s *Service) rollback(w http.ResponseWriter, r *http.Request) {
	purpose := r.PathValue("purpose")
	if !s.authorize(w, r, ActionRollback, purpose) {
		return
	}
	res, err := s.o.Rotator.Rollback(r.Context(), keyforge.Purpose(purpose))
	if !ok(err) {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rotateResponse{result: warn(err), KEKID: res.KEK.ID.String(), From: res.From, To: res.To, At: res.At})
}

type rewrapResponse struct {
	result
	Done     bool           `json:"done"`
	Versions map[string]any `json:"versions"`
}

func (s *Service) rewrap(w http.ResponseWriter, r *http.Request) {
	purpose := r.PathValue("purpose")
	if !s.authorize(w, r, ActionRewrap, purpose) {
		return
	}
	kek, err := s.o.Store.KEKForPurpose(r.Context(), keyforge.Purpose(purpose))
	if err != nil {
		fail(w, err)
		return
	}
	res, err := s.o.Rotator.RewrapAll(r.Context(), kek.ID, rotate.RewrapOptions{})
	if !ok(err) {
		fail(w, err)
		return
	}
	out := rewrapResponse{result: warn(err), Done: res.Done, Versions: map[string]any{}}
	for v, rr := range res.Versions {
		out.Versions[strconv.FormatUint(uint64(v), 10)] = map[string]int{"rewrapped": rr.Rewrapped, "skipped": rr.Skipped, "failed": rr.FailedCount}
	}
	writeJSON(w, http.StatusOK, out)
}

type stepResponse struct {
	result
	Outcome string `json:"outcome"`
	State   string `json:"state"`
	Reason  string `json:"reason,omitempty"`
}

// stepStatus maps a guard outcome onto a status: allowed is 200, an approval
// still outstanding is 202, and a denial is 409.
func stepStatus(o guard.Outcome) int {
	switch o {
	case guard.Pending:
		return http.StatusAccepted
	case guard.Denied:
		return http.StatusConflict
	}
	return http.StatusOK
}

func (s *Service) step(w http.ResponseWriter, res rotate.RetireResult, err error) {
	if !ok(err) {
		fail(w, err)
		return
	}
	writeJSON(w, stepStatus(res.Outcome), stepResponse{result: warn(err), Outcome: res.Outcome.String(), State: res.State.String(), Reason: res.Reason})
}

func (s *Service) requestRetire(w http.ResponseWriter, r *http.Request) {
	s.guarded(w, r, ActionRetireRequest, func(id envelope.ID, v uint32) {
		res, err := s.o.Rotator.RequestRetirement(r.Context(), id, v)
		s.step(w, res, err)
	})
}

func (s *Service) completeRetire(w http.ResponseWriter, r *http.Request) {
	s.guarded(w, r, ActionRetireComplete, func(id envelope.ID, v uint32) {
		res, err := s.o.Rotator.CompleteRetirement(r.Context(), id, v)
		s.step(w, res, err)
	})
}

func (s *Service) cancelRetire(w http.ResponseWriter, r *http.Request) {
	s.guarded(w, r, ActionRetireCancel, func(id envelope.ID, v uint32) {
		res, err := s.o.Rotator.CancelRetirement(r.Context(), id, v)
		s.step(w, res, err)
	})
}

func (s *Service) destroy(w http.ResponseWriter, r *http.Request) {
	s.guarded(w, r, ActionDestroy, func(id envelope.ID, v uint32) {
		res, err := s.o.Rotator.Destroy(r.Context(), id, v)
		s.step(w, res, err)
	})
}

type compromiseRequest struct {
	KeepMaterial bool `json:"keepMaterial"`
}

type compromiseResponse struct {
	result
	Replacement uint32 `json:"replacement,omitempty"`
	Rewrapped   int    `json:"rewrapped"`
	Remaining   int    `json:"remaining"`
	Retired     bool   `json:"retired"`
	Destroyed   bool   `json:"destroyed"`
	Guard       string `json:"guard"`
}

func (s *Service) compromiseKEK(w http.ResponseWriter, r *http.Request) {
	s.guarded(w, r, ActionCompromiseKEK, func(id envelope.ID, v uint32) {
		var req compromiseRequest
		if !decode(w, r, &req) {
			return
		}
		res, err := s.o.Rotator.CompromiseKEK(r.Context(), id, v, rotate.EmergencyKEKOptions{KeepMaterial: req.KeepMaterial})
		out := compromiseResponse{
			result: warn(err), Replacement: res.Replacement.To, Rewrapped: res.Rewrap.Rewrapped, Remaining: res.Remaining,
			Retired: res.Retired, Destroyed: res.Destroyed, Guard: res.Guard.Outcome.String(),
		}
		switch {
		case errors.Is(err, rotate.ErrEmergencyIncomplete):
			// Progress was made; say how far, and that it is to be repeated.
			writeJSON(w, http.StatusConflict, struct {
				ErrorBody
				Progress compromiseResponse `json:"progress"`
			}{ErrorBody{Error: ErrorDetail{Code: "emergency_incomplete", Message: rotate.ErrEmergencyIncomplete.Error()}}, out})
		case !ok(err):
			fail(w, err)
		default:
			writeJSON(w, http.StatusOK, out)
		}
	})
}

func (s *Service) dekPurpose(ctx context.Context, id envelope.ID) (string, bool) {
	rec, err := s.o.Store.GetDEK(ctx, id)
	if err != nil {
		return "", false
	}
	return string(rec.Purpose), true
}

type dekResponse struct {
	result
	State       string `json:"state"`
	Replacement string `json:"replacement,omitempty"`
	// EncryptionsUpperBound is the most encryptions that can have been made
	// under the exposed key; it can overstate.
	EncryptionsUpperBound uint64 `json:"encryptionsUpperBound,omitempty"`
}

func (s *Service) compromiseDEK(w http.ResponseWriter, r *http.Request) {
	id, ok1 := parseKEK(w, r.PathValue("id"))
	if !ok1 {
		return
	}
	purpose, found := s.dekPurpose(r.Context(), id)
	if !s.authorize(w, r, ActionCompromiseDEK, purpose) {
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", keyforge.ErrDEKNotFound.Error())
		return
	}
	res, err := s.o.Rotator.CompromiseDEK(r.Context(), id)
	if !ok(err) {
		fail(w, err)
		return
	}
	out := dekResponse{result: warn(err), State: res.Exposed.State.String(), EncryptionsUpperBound: res.EncryptionsUpperBound}
	if !res.Replacement.ID.IsZero() {
		out.Replacement = res.Replacement.ID.String()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) destroyDEK(w http.ResponseWriter, r *http.Request) {
	id, ok1 := parseKEK(w, r.PathValue("id"))
	if !ok1 {
		return
	}
	purpose, found := s.dekPurpose(r.Context(), id)
	if !s.authorize(w, r, ActionDestroyDEK, purpose) {
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", keyforge.ErrDEKNotFound.Error())
		return
	}
	res, err := s.o.Rotator.DestroyDEK(r.Context(), id)
	s.step(w, res, err)
}

type ackRequest struct {
	Generation uint64 `json:"generation"`
	Note       string `json:"note"`
}

type ackResponse struct {
	Provider     string `json:"provider"`
	Acknowledged uint64 `json:"acknowledged"`
}

func (s *Service) ackBackup(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, ActionBackupAck, "") {
		return
	}
	var req ackRequest
	if !decode(w, r, &req) {
		return
	}
	name := r.PathValue("provider")
	acker, found := s.o.Backups[name]
	if !found {
		writeError(w, http.StatusNotFound, "not_found", "no such provider keeps a backup that can be acknowledged")
		return
	}
	if req.Generation == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "a generation is required")
		return
	}
	if len(req.Note) > 1024 {
		writeError(w, http.StatusBadRequest, "invalid_request", "the note is too long")
		return
	}
	if err := acker.AckBackup(r.Context(), req.Generation, s.o.Clock.Now(), req.Note); err != nil {
		// The provider's own sentinels say what was wrong with the generation.
		writeError(w, http.StatusConflict, "ack_refused", ackReason(err))
		return
	}
	writeJSON(w, http.StatusOK, ackResponse{Provider: name, Acknowledged: req.Generation})
}

func ackReason(err error) string {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "the request was cancelled"
	default:
		return "the acknowledgement was refused: the generation is ahead of the keyring or older than the last acknowledgement"
	}
}

func (s *Service) shred(w http.ResponseWriter, r *http.Request) {
	purpose, subject := r.PathValue("purpose"), r.PathValue("subject")
	if !s.authorize(w, r, ActionShredRequest, purpose) {
		return
	}
	rec, err := s.o.Rotator.RequestShred(r.Context(), keyforge.Purpose(purpose), subject)
	if !ok(err) {
		fail(w, err)
		return
	}
	code := http.StatusAccepted // the erasure is not complete until the KEK versions are gone
	if rec.Complete() {
		code = http.StatusOK
	}
	writeJSON(w, code, struct {
		result
		DataKeys int  `json:"dataKeys"`
		Complete bool `json:"complete"`
		Versions int  `json:"pendingVersions"`
	}{warn(err), rec.DEKs, rec.Complete(), len(rec.Versions)})
}

func (s *Service) shredStatus(w http.ResponseWriter, r *http.Request) {
	purpose, subject := r.PathValue("purpose"), r.PathValue("subject")
	if !s.authorize(w, r, ActionShredRead, purpose) {
		return
	}
	st, err := s.o.Rotator.ShredStatus(r.Context(), keyforge.Purpose(purpose), subject)
	if err != nil {
		fail(w, err)
		return
	}
	s.emitRead(r, "read erasure status", purpose)
	writeJSON(w, http.StatusOK, struct {
		Complete   bool      `json:"complete"`
		Pending    int       `json:"pendingVersions"`
		ExpectedBy time.Time `json:"expectedBy,omitzero"`
	}{st.Complete, len(st.Pending), st.ExpectedBy})
}

type verifyResponse struct {
	OK      bool                    `json:"ok"`
	Results []keyforge.VerifyResult `json:"results"`
}

// verify round-trips a test value through every purpose, or through the one
// named in the optional `purpose` query parameter. It answers 200 when all pass
// and 503 with the same body when one does not, so a monitor can read the status.
func (s *Service) verify(w http.ResponseWriter, r *http.Request) {
	purpose := r.URL.Query().Get("purpose")
	if !s.authorize(w, r, ActionVerify, purpose) {
		return
	}
	if s.o.Verifier == nil {
		writeError(w, http.StatusNotImplemented, "not_configured", "verification is not configured")
		return
	}
	var ps []keyforge.Purpose
	if purpose != "" {
		ps = append(ps, keyforge.Purpose(purpose))
	}
	res := s.o.Verifier.Verify(r.Context(), ps...)
	out := verifyResponse{OK: true, Results: res}
	for _, v := range res {
		out.OK = out.OK && v.OK
	}
	code := http.StatusOK
	if !out.OK {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, out)
}
