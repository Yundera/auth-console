// Package server wires the HTTP API and the embedded single-page app.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/yundera/auth-console/internal/auth"
	"github.com/yundera/auth-console/internal/config"
	"github.com/yundera/auth-console/internal/dockerx"
	"github.com/yundera/auth-console/internal/envfile"
	"github.com/yundera/auth-console/internal/gatectl"
	"github.com/yundera/auth-console/internal/hostverb"
	"github.com/yundera/auth-console/internal/pubkey"
)

// Version is set at build time (-ldflags "-X .../server.Version=...").
var Version = "dev"

// HeaderCSRF must accompany every state-changing request (see csrfGuard).
const HeaderCSRF = "X-Auth-Console"

// runner is the part of dockerx the handlers use, so tests can fake the host.
type runner interface {
	RunOnHost(ctx context.Context, image string, argv []string) (*dockerx.RunResult, error)
	ImageOf(ctx context.Context, name string) (string, error)
}

type Server struct {
	cfg    config.Config
	authn  auth.Authenticator
	docker runner // nil when the socket is unavailable
	gate   gatectl.Client
	pubkey pubkey.Fetcher
	http   *http.Client

	supportMu  sync.Mutex
	supportKey *supportKeyCache
}

func New(cfg config.Config, uiFS fs.FS) http.Handler {
	return newServer(cfg).routes(uiFS)
}

func newServer(cfg config.Config) *Server {
	s := &Server{
		cfg:    cfg,
		gate:   gatectl.Client{BaseURL: cfg.GateURL, Secret: []byte(cfg.AssertionSecret)},
		pubkey: pubkey.Fetcher{TrustedSuffixes: cfg.TrustedPubkeyHostSuffixes},
		http:   &http.Client{Timeout: 10 * time.Second},
	}
	s.authn = auth.Authenticator{Secret: []byte(cfg.AssertionSecret), Audience: cfg.AssertionAudience}
	if cfg.AssertionSecret == "" && cfg.DevIdentity != "" && cfg.Env == "development" {
		log.Printf("WARNING: DEV_IDENTITY=%q — every request is treated as that identity", cfg.DevIdentity)
		user, groups, _ := strings.Cut(cfg.DevIdentity, ":")
		id := &auth.Identity{User: user, Method: "dev"}
		for _, g := range strings.Split(groups, ",") {
			if g = strings.TrimSpace(g); g != "" {
				id.Groups = append(id.Groups, g)
			}
		}
		s.authn.Dev = id
	} else if cfg.AssertionSecret == "" {
		log.Print("WARNING: IDENTITY_ASSERTION_SECRET is not set — every API request will be refused")
	}
	if cfg.HostRoot == "" {
		log.Print("WARNING: HOST_ROOT is not set — every host action will fail")
	}
	if d, err := dockerx.New(); err != nil {
		log.Printf("docker unavailable: %v", err)
	} else {
		s.docker = d
	}
	return s
}

func (s *Server) routes(uiFS fs.FS) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.Recoverer, securityHeaders)

	// The only unauthenticated route, matching the gate's ALLOWED_PATHS.
	r.Get("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": Version})
	})

	r.Route("/api", func(api chi.Router) {
		api.Use(s.authn.RequireUser)
		api.Use(csrfGuard)

		// Any signed-in person: their own account.
		api.Get("/me", s.handleMe)
		api.Get("/capabilities", s.handleCapabilities)
		api.Get("/onboarding", s.handleOnboarding)

		// Admins only.
		api.Group(func(adm chi.Router) {
			adm.Use(auth.RequireAdmin)
			adm.Get("/users", s.handleUsersList)
			adm.Post("/users", s.handleUsersAdd)
			adm.Delete("/users/{username}", s.handleUsersDelete)
			adm.Post("/users/{username}/reset-password", s.handleUsersResetPassword)
			adm.Put("/users/{username}/email", s.handleUsersSetEmail)

			adm.Get("/access", s.handleAccess)
			adm.Post("/access/keys", s.handleAccessAddKey)
			adm.Delete("/access/keys", s.handleAccessRemoveKey)
			adm.Get("/access/fetch-pubkey", s.handleFetchPubkey)
			adm.Get("/access/support", s.handleSupportGet)
			adm.Put("/access/support", s.handleSupportPut)
		})

		api.NotFound(func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusNotFound, "not found")
		})
	})

	r.Handle("/*", spaHandler(uiFS))
	return r
}

// ---- host view -----------------------------------------------------------

// env reads the platform .env fresh, through the read-only mount.
func (s *Server) env() envfile.Env {
	e, err := envfile.Load(s.cfg.HostRootMount)
	if err != nil {
		return envfile.Env{}
	}
	return e
}

// onMount maps a host path under HOST_ROOT to its place under the mount.
func (s *Server) onMount(hostPath string) (string, bool) {
	root := s.cfg.HostRoot
	if root == "" || (hostPath != root && !strings.HasPrefix(hostPath, root+"/")) {
		return "", false
	}
	return filepath.Join(s.cfg.HostRootMount, strings.TrimPrefix(hostPath, root)), true
}

func (s *Server) exists(hostPath string) bool {
	p, ok := s.onMount(hostPath)
	if !ok {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// scripts resolves the template's scripts directory on the host.
func (s *Server) scripts() hostverb.Scripts {
	if s.cfg.HostScripts != "" {
		return hostverb.Scripts(s.cfg.HostScripts)
	}
	yundera := path.Join(s.cfg.HostRoot, "template", "scripts")
	if s.exists(path.Join(yundera, "tools", "authelia-user-manager.sh")) {
		return hostverb.Scripts(yundera)
	}
	return hostverb.Scripts(path.Join(s.cfg.HostRoot, "scripts"))
}

func (s *Server) hasTool(name string) bool {
	return s.exists(path.Join(string(s.scripts()), "tools", name))
}

type capabilities struct {
	// Onboarding: the Yundera onboarding status line (tools/onboarding.sh).
	Onboarding bool `json:"onboarding"`
	// Support: the Yundera support-access toggle — needs the operator API
	// and tools/feature-support-key.sh.
	Support bool `json:"support"`
	// DashboardAccount is the host account the Yundera admin app reaches the
	// host as; its local-admin-access key cannot be removed here. Empty on FOSS.
	DashboardAccount string `json:"dashboardAccount"`
}

func (s *Server) caps() capabilities {
	c := capabilities{
		Onboarding: s.hasTool("onboarding.sh"),
		Support:    s.cfg.OperatorAPI != "" && s.hasTool("feature-support-key.sh"),
	}
	if c.Onboarding || c.Support {
		c.DashboardAccount = "admin"
	}
	return c
}

// ---- verbs ---------------------------------------------------------------

var errNoDocker = errors.New("docker socket unavailable")

// runVerb runs a host verb from this container's own image, on a context
// detached from the request (see dockerx.RunOnHost), bounded so a hung script
// cannot pin the runner forever.
func (s *Server) runVerb(reqCtx context.Context, v hostverb.Verb) (*dockerx.RunResult, error) {
	if s.docker == nil {
		return nil, errNoDocker
	}
	image := s.cfg.RunnerImage
	if image == "" {
		img, err := s.docker.ImageOf(reqCtx, s.cfg.SelfContainer)
		if err != nil {
			return nil, errors.New("cannot determine runner image (set RUNNER_IMAGE): " + err.Error())
		}
		image = img
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return s.docker.RunOnHost(ctx, image, v.Argv)
}

// scriptError is a failed verb's error. The script's own `ERROR: …` line (what
// settings-center-app's describeUserError showed) is a refusal — the request's
// fault, 400. Anything else (a missing script, a crash) is the host's — 502.
func scriptError(res *dockerx.RunResult) error {
	for _, out := range []string{res.Stderr, res.Stdout} {
		for _, line := range strings.Split(out, "\n") {
			if i := strings.Index(line, "ERROR:"); i >= 0 {
				if msg := strings.TrimSpace(line[i+len("ERROR:"):]); msg != "" {
					return refused(msg)
				}
			}
		}
	}
	msg := strings.TrimSpace(res.Stderr)
	if len(msg) > 300 {
		msg = "…" + msg[len(msg)-300:]
	}
	if msg == "" {
		msg = "no output"
	}
	return fmt.Errorf("host action failed (exit %d): %s", res.ExitCode, msg)
}

// lastJSON decodes the last line of stdout that looks like JSON — the verbs'
// answer — into v.
func lastJSON(stdout string, v any) error {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.HasPrefix(l, "{") || strings.HasPrefix(l, "[") {
			return json.Unmarshal([]byte(l), v)
		}
	}
	return errors.New("host action returned no JSON")
}

// runJSON runs v and decodes its JSON answer. A script refusal (non-zero exit)
// becomes errRefused with the script's message: it is the request's fault
// (400), unlike a runner failure (502).
func (s *Server) runJSON(ctx context.Context, v hostverb.Verb, out any) error {
	res, err := s.runVerb(ctx, v)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return scriptError(res)
	}
	if err := lastJSON(res.Stdout, out); err != nil {
		return err
	}
	return nil
}

type refused string

func (r refused) Error() string { return string(r) }

// verbError maps a verb failure to a status.
func verbError(w http.ResponseWriter, err error) {
	var r refused
	switch {
	case errors.As(err, &r):
		writeError(w, http.StatusBadRequest, string(r))
	case errors.Is(err, dockerx.ErrBusy):
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeError(w, http.StatusBadGateway, err.Error())
	}
}

// ---- plumbing ------------------------------------------------------------

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// csrfGuard requires a custom header on state-changing requests. A cross-site
// page cannot set it without a CORS preflight, and this server answers none,
// so the gate's session cookie alone can never change an account or a key.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(HeaderCSRF) != "1" {
			writeError(w, http.StatusForbidden, "missing "+HeaderCSRF+" header")
			return
		}
		next.ServeHTTP(w, r)
	})
}
