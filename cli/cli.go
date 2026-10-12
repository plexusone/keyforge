// Package cli is keyforge's command line: Cobra commands over the HTTP control
// plane.
//
// The commands are a client of the control plane and hold no logic of their
// own, so there is one implementation of each operation and the command line
// cannot do what the service would refuse. Two transports are offered:
//
//   - A remote server, named by --server or KEYFORGE_SERVER, with a bearer
//     token from --token-file or KEYFORGE_TOKEN. This is the standalone
//     `keyforge` binary.
//   - An in-process handler, for a host that embeds the commands in its own
//     binary and has the control plane in the same process. No network is
//     involved, and the host's own authorizer and actor naming apply.
//
// A few commands need no server: generating a root key, and reading the header
// of a keyring file.
package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/plexusone/keyforge/provider/local"
)

// Options configures the command tree.
type Options struct {
	// Handler, when set, is the control plane in this process; --server is then
	// not needed and no network is used.
	Handler http.Handler
	// Out and Err default to the standard streams.
	Out, Err io.Writer
	// HTTPClient is used for a remote server. The default has a timeout.
	HTTPClient *http.Client
	// Env reads an environment variable; the default is os.Getenv.
	Env func(string) string
}

// NewRootCommand returns the `keyforge` command with every subcommand attached.
func NewRootCommand(opts Options) *cobra.Command {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.Err == nil {
		opts.Err = os.Stderr
	}
	if opts.Env == nil {
		opts.Env = os.Getenv
	}
	a := &app{opts: opts}

	root := &cobra.Command{
		Use:           "keyforge",
		Short:         "Encryption and signing key lifecycle",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(opts.Out)
	root.SetErr(opts.Err)
	pf := root.PersistentFlags()
	pf.StringVar(&a.server, "server", "", "base URL of the control plane (or KEYFORGE_SERVER)")
	pf.StringVar(&a.tokenFile, "token-file", "", "file holding a bearer token (or KEYFORGE_TOKEN)")
	pf.BoolVar(&a.asJSON, "json", false, "print the response as JSON")
	pf.DurationVar(&a.timeout, "timeout", 60*time.Second, "how long to wait for the control plane")

	root.AddCommand(
		a.statusCmd(), a.healthCmd(), a.purposesCmd(), a.rotateCmd(), a.rollbackCmd(), a.rewrapCmd(),
		a.retireCmd(), a.destroyCmd(), a.compromiseCmd(), a.datakeyCmd(), a.backupCmd(), a.shredCmd(),
		a.verifyCmd(), a.keyringCmd(), a.rootkeyCmd(),
	)
	return root
}

type app struct {
	opts      Options
	server    string
	tokenFile string
	asJSON    bool
	timeout   time.Duration
}

// ---- transport ----

// APIError is an error response from the control plane.
type APIError struct {
	Status  int
	Code    string
	Message string
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("the control plane answered %d", e.Status)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (a *app) token() (string, error) {
	if a.tokenFile != "" {
		b, err := os.ReadFile(a.tokenFile)
		if err != nil {
			return "", fmt.Errorf("reading the token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(a.opts.Env("KEYFORGE_TOKEN")), nil
}

// call sends a request and returns the body. An error response is returned as an
// [*APIError] along with its body, so a command can still show an answer such as
// a guard's denial that is not a failure of the request.
func (a *app) call(ctx context.Context, method, path string, body any) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}

	var (
		client = a.opts.HTTPClient
		base   string
	)
	switch {
	case a.opts.Handler != nil:
		client = &http.Client{Transport: handlerTransport{a.opts.Handler}}
		base = "http://keyforge.invalid"
	default:
		base = a.server
		if base == "" {
			base = a.opts.Env("KEYFORGE_SERVER")
		}
		if base == "" {
			return nil, errors.New("no control plane: give --server or set KEYFORGE_SERVER")
		}
		if client == nil {
			client = &http.Client{}
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok, err := a.token(); err != nil {
		return nil, err
	} else if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := client.Do(req)
	if err != nil {
		// The URL can carry a host and a path but never the token, which is in
		// a header; still, report only what failed.
		return nil, fmt.Errorf("reaching the control plane: %w", unwrapURLError(err))
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(b, &e) //nolint:errcheck // a non-JSON error body is reported by its status alone
		return b, &APIError{Status: res.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	}
	return b, nil
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// handlerTransport serves requests from an in-process handler.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := &recorder{header: http.Header{}, code: http.StatusOK}
	t.h.ServeHTTP(rec, r)
	return &http.Response{
		StatusCode: rec.code, Status: strconv.Itoa(rec.code), Header: rec.header,
		Body: io.NopCloser(bytes.NewReader(rec.body.Bytes())), Request: r, ContentLength: int64(rec.body.Len()),
	}, nil
}

type recorder struct {
	header http.Header
	body   bytes.Buffer
	code   int
	wrote  bool
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.body.Write(b)
}
func (r *recorder) WriteHeader(c int) {
	if !r.wrote {
		r.code = c
		r.wrote = true
	}
}

// ---- output ----

// show prints a response: the raw JSON with --json, otherwise through render.
func (a *app) show(b []byte, render func(w io.Writer, v map[string]any)) error {
	if a.asJSON {
		var buf bytes.Buffer
		if err := json.Indent(&buf, b, "", "  "); err != nil {
			_, err = a.opts.Out.Write(b)
			return err
		}
		buf.WriteByte('\n')
		_, err := a.opts.Out.Write(buf.Bytes())
		return err
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		_, err = a.opts.Out.Write(b)
		return err
	}
	render(a.opts.Out, v)
	if ws, ok := v["warnings"].([]any); ok {
		for _, w := range ws {
			fmt.Fprintf(a.opts.Err, "warning: %v\n", w)
		}
	}
	return nil
}

func str(v map[string]any, k string) string {
	switch x := v[k].(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return ""
}

// kv prints the given keys of v as "key: value" lines, skipping absent ones.
func kv(w io.Writer, v map[string]any, keys ...string) {
	for _, k := range keys {
		if s := str(v, k); s != "" {
			fmt.Fprintf(w, "%-18s %s\n", k+":", s)
		}
	}
}

// ---- commands ----

func (a *app) run(cmd *cobra.Command, method, path string, body any, render func(io.Writer, map[string]any)) error {
	b, err := a.call(cmd.Context(), method, path, body)
	if err != nil {
		var api *APIError
		// An answer that is not a failure of the request, such as a guard's
		// denial, is shown, and the command still exits non-zero.
		if errors.As(err, &api) && b != nil && api.Status == http.StatusConflict {
			if shown := a.show(b, render); shown == nil {
				return err
			}
		}
		return err
	}
	return a.show(b, render)
}

func (a *app) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use: "status", Short: "Show the state of every key, what is overdue, backups and provider health", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.run(cmd, "GET", "/v1/status", nil, renderStatus)
		},
	}
}

func (a *app) healthCmd() *cobra.Command {
	return &cobra.Command{
		Use: "health", Short: "Exit non-zero, listing the problems, unless everything is healthy", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			b, err := a.call(cmd.Context(), "GET", "/v1/health", nil)
			var api *APIError
			if err != nil && !(errors.As(err, &api) && api.Status == http.StatusServiceUnavailable) {
				return err
			}
			if shown := a.show(b, func(w io.Writer, v map[string]any) {
				fmt.Fprintf(w, "healthy: %s\n", str(v, "healthy"))
				if ps, ok := v["problems"].([]any); ok {
					for _, p := range ps {
						fmt.Fprintf(w, "  - %v\n", p)
					}
				}
			}); shown != nil {
				return shown
			}
			return err
		},
	}
}

func (a *app) purposesCmd() *cobra.Command {
	c := &cobra.Command{Use: "purposes", Short: "List purposes or show one"}
	c.AddCommand(&cobra.Command{
		Use: "list", Short: "List every purpose and its keys", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.run(cmd, "GET", "/v1/purposes", nil, func(w io.Writer, v map[string]any) {
				ps, _ := v["purposes"].([]any)
				for _, p := range ps {
					renderPurpose(w, p.(map[string]any))
				}
			})
		},
	})
	c.AddCommand(&cobra.Command{
		Use: "show <purpose>", Short: "Show one purpose", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "GET", "/v1/purposes/"+url.PathEscape(args[0]), nil, func(w io.Writer, v map[string]any) { renderPurpose(w, v) })
		},
	})
	return c
}

func (a *app) rotateCmd() *cobra.Command {
	return &cobra.Command{
		Use: "rotate <purpose>", Short: "Activate the next key-encryption key version for a purpose", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "POST", "/v1/purposes/"+url.PathEscape(args[0])+"/rotate", nil, func(w io.Writer, v map[string]any) {
				fmt.Fprintf(w, "version %s is now active, replacing %s\n", str(v, "to"), str(v, "from"))
				kv(w, v, "kekId", "at")
			})
		},
	}
}

func (a *app) rollbackCmd() *cobra.Command {
	return &cobra.Command{
		Use: "rollback <purpose>", Short: "Reactivate the most recent decrypt-only version", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "POST", "/v1/purposes/"+url.PathEscape(args[0])+"/rollback", nil, func(w io.Writer, v map[string]any) {
				fmt.Fprintf(w, "version %s is active again, replacing %s\n", str(v, "to"), str(v, "from"))
			})
		},
	}
}

func (a *app) rewrapCmd() *cobra.Command {
	return &cobra.Command{
		Use: "rewrap <purpose>", Short: "Move data keys off every version that is not active", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "POST", "/v1/purposes/"+url.PathEscape(args[0])+"/rewrap", nil, func(w io.Writer, v map[string]any) {
				vs, _ := v["versions"].(map[string]any)
				keys := make([]string, 0, len(vs))
				for k := range vs {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					m, _ := vs[k].(map[string]any)
					fmt.Fprintf(w, "version %s: %s moved, %s skipped, %s failed\n", k, str(m, "rewrapped"), str(m, "skipped"), str(m, "failed"))
				}
				fmt.Fprintf(w, "done: %s\n", str(v, "done"))
			})
		},
	}
}

func stepPath(kek, version, tail string) string {
	return "/v1/keks/" + url.PathEscape(kek) + "/versions/" + url.PathEscape(version) + "/" + tail
}

func renderStep(w io.Writer, v map[string]any) {
	fmt.Fprintf(w, "outcome: %s\n", str(v, "outcome"))
	fmt.Fprintf(w, "state:   %s\n", str(v, "state"))
	if r := str(v, "reason"); r != "" {
		fmt.Fprintf(w, "reason:  %s\n", r)
	}
}

func (a *app) retireCmd() *cobra.Command {
	c := &cobra.Command{Use: "retire", Short: "Retire a key-encryption key version, in steps"}
	for _, s := range []struct{ use, short, tail string }{
		{"request <kek> <version>", "Start the retirement delay for a decrypt-only version", "retire"},
		{"complete <kek> <version>", "Retire a version whose delay has passed, if the guard allows", "retire/complete"},
		{"cancel <kek> <version>", "Return a retire-requested version to decrypt-only", "retire/cancel"},
	} {
		c.AddCommand(&cobra.Command{
			Use: s.use, Short: s.short, Args: cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				return a.run(cmd, "POST", stepPath(args[0], args[1], s.tail), nil, renderStep)
			},
		})
	}
	return c
}

func (a *app) destroyCmd() *cobra.Command {
	return &cobra.Command{
		Use: "destroy <kek> <version>", Short: "Destroy a retired version's material at the provider, if the guard allows", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "POST", stepPath(args[0], args[1], "destroy"), nil, renderStep)
		},
	}
}

func (a *app) compromiseCmd() *cobra.Command {
	var keep bool
	c := &cobra.Command{
		Use: "compromise <kek> <version>", Short: "Emergency: replace, re-wrap away from, retire and destroy an exposed version", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "POST", stepPath(args[0], args[1], "compromise"), map[string]any{"keepMaterial": keep}, func(w io.Writer, v map[string]any) {
				kv(w, v, "replacement", "rewrapped", "remaining", "retired", "destroyed", "guard")
			})
		},
	}
	c.Flags().BoolVar(&keep, "keep-material", false, "stop after retirement and leave the material at the provider")
	return c
}

func (a *app) datakeyCmd() *cobra.Command {
	c := &cobra.Command{Use: "datakey", Short: "Handle an exposed data key"}
	c.AddCommand(&cobra.Command{
		Use: "compromise <id>", Short: "Replace an exposed data key and mark it compromised", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "POST", "/v1/datakeys/"+url.PathEscape(args[0])+"/compromise", nil, func(w io.Writer, v map[string]any) {
				kv(w, v, "state", "replacement", "encryptionsUpperBound")
			})
		},
	})
	c.AddCommand(&cobra.Command{
		Use: "destroy <id>", Short: "Destroy a data key once what it protects has been re-encrypted", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "POST", "/v1/datakeys/"+url.PathEscape(args[0])+"/destroy", nil, renderStep)
		},
	})
	return c
}

func (a *app) backupCmd() *cobra.Command {
	var gen uint64
	var note string
	ack := &cobra.Command{
		Use: "ack <provider>", Short: "Record that a copy of a provider's keyring is safely stored", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "POST", "/v1/backups/"+url.PathEscape(args[0])+"/ack", map[string]any{"generation": gen, "note": note}, func(w io.Writer, v map[string]any) {
				fmt.Fprintf(w, "acknowledged generation %s of %s\n", str(v, "acknowledged"), str(v, "provider"))
			})
		},
	}
	ack.Flags().Uint64Var(&gen, "generation", 0, "the generation of the copy that was stored (see `keyring inspect`)")
	ack.Flags().StringVar(&note, "note", "", "where the copy is kept")
	_ = ack.MarkFlagRequired("generation") //nolint:errcheck // the flag is defined on the line above
	c := &cobra.Command{Use: "backup", Short: "Keyring backup acknowledgement"}
	c.AddCommand(ack)
	return c
}

func (a *app) shredCmd() *cobra.Command {
	c := &cobra.Command{Use: "shred", Short: "Erase a subject by destroying its data keys"}
	c.AddCommand(&cobra.Command{
		Use: "request <purpose> <subject>", Short: "Destroy a subject's keys and start its erasure", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "POST", shredPath(args), nil, func(w io.Writer, v map[string]any) {
				kv(w, v, "dataKeys", "complete", "pendingVersions")
			})
		},
	})
	c.AddCommand(&cobra.Command{
		Use: "status <purpose> <subject>", Short: "Show what remains before an erasure is complete", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(cmd, "GET", shredPath(args), nil, func(w io.Writer, v map[string]any) {
				kv(w, v, "complete", "pendingVersions", "expectedBy")
			})
		},
	})
	return c
}

func shredPath(args []string) string {
	return "/v1/purposes/" + url.PathEscape(args[0]) + "/subjects/" + url.PathEscape(args[1]) + "/shred"
}

func (a *app) verifyCmd() *cobra.Command {
	var purpose string
	c := &cobra.Command{
		Use: "verify", Short: "Round-trip a test value through each purpose's keys, from cold", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := "/v1/verify"
			if purpose != "" {
				path += "?purpose=" + url.QueryEscape(purpose)
			}
			b, err := a.call(cmd.Context(), "POST", path, nil)
			var api *APIError
			if err != nil && !(errors.As(err, &api) && api.Status == http.StatusServiceUnavailable) {
				return err
			}
			if shown := a.show(b, func(w io.Writer, v map[string]any) {
				rs, _ := v["results"].([]any)
				for _, r := range rs {
					m, _ := r.(map[string]any)
					state := "ok"
					if ok, _ := m["ok"].(bool); !ok {
						state = "FAILED"
					}
					fmt.Fprintf(w, "%-24s %s\n", str(m, "purpose"), state)
					cs, _ := m["checks"].([]any)
					for _, c := range cs {
						cm, _ := c.(map[string]any)
						fmt.Fprintf(w, "  %-10s %s\n", str(cm, "mode"), str(cm, "outcome"))
					}
				}
			}); shown != nil {
				return shown
			}
			if err != nil {
				return errors.New("verification failed")
			}
			return nil
		},
	}
	c.Flags().StringVar(&purpose, "purpose", "", "verify one purpose instead of all")
	return c
}

// keyringCmd and rootkeyCmd need no control plane.

func (a *app) keyringCmd() *cobra.Command {
	c := &cobra.Command{Use: "keyring", Short: "Work with a local keyring file"}
	c.AddCommand(&cobra.Command{
		Use: "inspect <file>", Short: "Show a keyring file's generation and root key identifier, without the root key", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			gen, id, err := local.Peek(args[0])
			if err != nil {
				return err
			}
			if a.asJSON {
				return json.NewEncoder(a.opts.Out).Encode(map[string]any{"generation": gen, "rootKeyId": id})
			}
			fmt.Fprintf(a.opts.Out, "generation:  %d\nrootKeyId:   %s\n", gen, id)
			return nil
		},
	})
	return c
}

func (a *app) rootkeyCmd() *cobra.Command {
	c := &cobra.Command{Use: "rootkey", Short: "Work with the local provider's root key"}
	c.AddCommand(&cobra.Command{
		Use: "generate", Short: "Print a new root key: 32 random bytes as base64", Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			k := make([]byte, local.RootKeySize)
			defer clear(k)
			if _, err := rand.Read(k); err != nil {
				return err
			}
			fmt.Fprintln(a.opts.Out, base64.StdEncoding.EncodeToString(k))
			fmt.Fprintln(a.opts.Err, "Store this in a secret manager and keep a second copy offline. It is not kept anywhere else.")
			return nil
		},
	})
	return c
}

// ---- rendering ----

func renderPurpose(w io.Writer, p map[string]any) {
	fmt.Fprintf(w, "%s\n", str(p, "purpose"))
	if e := str(p, "error"); e != "" {
		fmt.Fprintf(w, "  error: %s\n", e)
		return
	}
	fmt.Fprintf(w, "  provider: %s   kek: %s   active version: %s\n", str(p, "provider"), str(p, "kekId"), str(p, "activeVersion"))
	if n := str(p, "nextRotation"); n != "" {
		over := ""
		if o, _ := p["overdue"].(bool); o {
			over = "   OVERDUE"
		}
		fmt.Fprintf(w, "  next rotation: %s%s\n", n, over)
	}
	vs, _ := p["versions"].([]any)
	for _, v := range vs {
		m, _ := v.(map[string]any)
		extra := ""
		if r := str(m, "references"); r != "" && r != "0" {
			extra = "  references: " + r
		}
		if ok, _ := m["retirable"].(bool); ok {
			extra += "  retirable"
		}
		fmt.Fprintf(w, "    version %-4s %-17s%s\n", str(m, "version"), str(m, "state"), extra)
	}
	if dk, ok := p["dataKeys"].(map[string]any); ok {
		keys := make([]string, 0, len(dk))
		for k := range dk {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %v", k, dk[k]))
		}
		fmt.Fprintf(w, "  data keys: %s\n", strings.Join(parts, ", "))
	}
}

func renderStatus(w io.Writer, v map[string]any) {
	if h, _ := v["healthy"].(bool); h {
		fmt.Fprintln(w, "healthy")
	} else {
		fmt.Fprintln(w, "NOT HEALTHY")
		if ps, ok := v["problems"].([]any); ok {
			for _, p := range ps {
				fmt.Fprintf(w, "  - %v\n", p)
			}
		}
	}
	if c, ok := v["crypto"].(map[string]any); ok {
		fmt.Fprintf(w, "\ncrypto:    profile %s, FIPS mode %s, module %s\n", str(c, "profile"), str(c, "fipsMode"), str(c, "moduleVersion"))
		if as, ok := c["algorithms"].([]any); ok {
			names := make([]string, 0, len(as))
			for _, a := range as {
				names = append(names, fmt.Sprint(a))
			}
			fmt.Fprintf(w, "           algorithms: %s\n", strings.Join(names, ", "))
		}
	}
	if ps, ok := v["providers"].([]any); ok {
		fmt.Fprintln(w, "\nproviders:")
		for _, p := range ps {
			m, _ := p.(map[string]any)
			state := "healthy"
			if h, _ := m["healthy"].(bool); !h {
				state = "UNHEALTHY: " + str(m, "error")
			}
			fmt.Fprintf(w, "  %-18s %s\n", str(m, "name"), state)
			if b, ok := m["backup"].(map[string]any); ok {
				fmt.Fprintf(w, "    backup: generation %s, acknowledged %s, behind %s\n", str(b, "generation"), str(b, "acknowledged"), str(b, "behind"))
			}
		}
	}
	if ps, ok := v["purposes"].([]any); ok {
		fmt.Fprintln(w)
		for _, p := range ps {
			renderPurpose(w, p.(map[string]any))
		}
	}
	if ss, ok := v["shreds"].([]any); ok && len(ss) > 0 {
		fmt.Fprintln(w, "\nerasures in progress:")
		for _, s := range ss {
			m, _ := s.(map[string]any)
			fmt.Fprintf(w, "  %s / %s: %s version(s) to go, expected by %s\n", str(m, "purpose"), str(m, "subject"), str(m, "pendingVersions"), str(m, "expectedBy"))
		}
	}
	if j, ok := v["jobs"].(map[string]any); ok {
		fmt.Fprintf(w, "\njobs: %s in flight, %s waiting\n", str(j, "inFlight"), str(j, "waiting"))
		if fs, ok := j["failed"].([]any); ok {
			for _, f := range fs {
				m, _ := f.(map[string]any)
				fmt.Fprintf(w, "  failed: %s (%s in a row)\n", str(m, "kind"), str(m, "consecutive"))
			}
		}
	}
}
