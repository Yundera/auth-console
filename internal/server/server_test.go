package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yundera/auth-console/internal/auth"
	"github.com/yundera/auth-console/internal/config"
	"github.com/yundera/auth-console/internal/dockerx"
)

// fakeRunner answers host verbs from a function of their argv.
type fakeRunner struct {
	calls [][]string
	fn    func(argv []string) *dockerx.RunResult
}

func (f *fakeRunner) RunOnHost(_ context.Context, _ string, argv []string) (*dockerx.RunResult, error) {
	f.calls = append(f.calls, argv)
	return f.fn(argv), nil
}

func (f *fakeRunner) ImageOf(context.Context, string) (string, error) {
	return "auth-console:test", nil
}

var ui = fstest.MapFS{
	"index.html":      {Data: []byte("<html>app</html>")},
	"assets/app-1.js": {Data: []byte("js")},
}

// hostRoot builds a fake mesh root on disk: the .env and the one script the
// scripts-dir detection looks for.
func hostRoot(t *testing.T, env string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(dir, "scripts", "tools"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "scripts", "tools", "authelia-user-manager.sh"), nil, 0o755)
	return dir
}

func testServer(t *testing.T, user string, groups []string, fr *fakeRunner) (http.Handler, *Server) {
	t.Helper()
	mount := hostRoot(t, "DOMAIN=box.nsl.sh\nLOCAL_ADMIN_USER=owner\n")
	s := newServer(config.Config{HostRoot: "/DATA/AppData/mesh", HostRootMount: mount, AssertionAudience: "auth-console", GateURL: "http://127.0.0.1:1"})
	if user != "" {
		s.authn.Dev = &auth.Identity{User: user, Groups: groups, Method: "oidc"}
	}
	if fr != nil {
		s.docker = fr
	} else {
		s.docker = nil
	}
	return s.routes(ui), s
}

func do(h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var csrf = map[string]string{HeaderCSRF: "1"}

func TestHealthIsPublic(t *testing.T) {
	h, _ := testServer(t, "", nil, nil)
	if rec := do(h, http.MethodGet, "/api/health", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("health = %d", rec.Code)
	}
	for _, p := range []string{"/api/me", "/api/users", "/api/access", "/api/nope"} {
		if rec := do(h, http.MethodGet, p, "", nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", p, rec.Code)
		}
	}
}

func TestNonAdminSeesOnlyTheirAccount(t *testing.T) {
	h, _ := testServer(t, "bob", []string{"users"}, nil)
	rec := do(h, http.MethodGet, "/api/me", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("me = %d", rec.Code)
	}
	var me map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me["isAdmin"] != false || me["localAuthUrl"] != "https://local-auth-box.nsl.sh" {
		t.Errorf("me = %v", me)
	}
	for _, p := range []string{"/api/users", "/api/access", "/api/access/support"} {
		if rec := do(h, http.MethodGet, p, "", nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", p, rec.Code)
		}
	}
}

func TestCSRF(t *testing.T) {
	h, _ := testServer(t, "alice", []string{"admins"}, nil)
	if rec := do(h, http.MethodPost, "/api/users", "{}", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("POST without header = %d", rec.Code)
	}
}

func TestUsersList(t *testing.T) {
	fr := &fakeRunner{fn: func(argv []string) *dockerx.RunResult {
		return &dockerx.RunResult{Stdout: `[{"username":"owner","displayname":"O","email":"o@x.io","groups":["admins"],"disabled":false},{"username":"bob","displayname":"B","email":"b@x.io","groups":null,"disabled":false}]` + "\n", Stderr: "some log line\n"}
	}}
	h, _ := testServer(t, "alice", []string{"admins"}, fr)
	rec := do(h, http.MethodGet, "/api/users", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("users = %d %s", rec.Code, rec.Body)
	}
	if got := strings.Join(fr.calls[0], " "); got != "bash /DATA/AppData/mesh/scripts/tools/authelia-user-manager.sh list" {
		t.Errorf("argv = %q", got)
	}
	var out struct {
		Users []struct {
			Username  string   `json:"username"`
			Groups    []string `json:"groups"`
			Protected bool     `json:"protected"`
		} `json:"users"`
		CurrentUser string `json:"currentUser"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	// No `protected` from an older script: derived from LOCAL_ADMIN_USER.
	if !out.Users[0].Protected || out.Users[1].Protected || out.Users[1].Groups == nil || out.CurrentUser != "alice" {
		t.Errorf("out = %+v", out)
	}
}

func TestScriptRefusalIs400(t *testing.T) {
	fr := &fakeRunner{fn: func([]string) *dockerx.RunResult {
		return &dockerx.RunResult{ExitCode: 1, Stderr: "ERROR: refusing to delete 'owner': it is the owner account\n"}
	}}
	h, _ := testServer(t, "alice", []string{"admins"}, fr)
	rec := do(h, http.MethodDelete, "/api/users/owner", "", csrf)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "refusing to delete 'owner'") {
		t.Fatalf("delete owner = %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, http.MethodDelete, "/api/users/alice", "", csrf); rec.Code != http.StatusBadRequest {
		t.Errorf("delete self = %d", rec.Code)
	}
	if rec := do(h, http.MethodDelete, "/api/users/$(id)", "", csrf); rec.Code != http.StatusBadRequest {
		t.Errorf("hostile username = %d", rec.Code)
	}
	if len(fr.calls) != 1 {
		t.Errorf("runner called %d times, want 1 (self and hostile never reach the host)", len(fr.calls))
	}
}

func TestAddKeyExitCodes(t *testing.T) {
	code := int64(2)
	fr := &fakeRunner{fn: func([]string) *dockerx.RunResult {
		return &dockerx.RunResult{ExitCode: code, Stdout: "USER_NOT_FOUND\n"}
	}}
	h, _ := testServer(t, "alice", []string{"admins"}, fr)
	body := `{"username":"ghost","publicKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb0ZsYk2mT3OE9d3zVxj8pGQv5c7Qv1aJdR3r7hH0cK user-x"}`
	if rec := do(h, http.MethodPost, "/api/access/keys", body, csrf); rec.Code != http.StatusNotFound {
		t.Errorf("unknown user = %d", rec.Code)
	}
	code = 0
	fr.fn = func([]string) *dockerx.RunResult { return &dockerx.RunResult{Stdout: "ADDED\n"} }
	rec := do(h, http.MethodPost, "/api/access/keys", body, csrf)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"added"`) {
		t.Errorf("add = %d %s", rec.Code, rec.Body)
	}
}

func TestNoDockerIs502(t *testing.T) {
	h, _ := testServer(t, "alice", []string{"admins"}, nil)
	if rec := do(h, http.MethodGet, "/api/users", "", nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("users without docker = %d", rec.Code)
	}
}

func TestCapabilitiesOnFOSS(t *testing.T) {
	h, _ := testServer(t, "alice", []string{"admins"}, nil)
	rec := do(h, http.MethodGet, "/api/capabilities", "", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"onboarding":false,"support":false,"dashboardAccount":""}`+"\n" {
		t.Fatalf("caps = %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, http.MethodGet, "/api/onboarding", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("onboarding on FOSS = %d", rec.Code)
	}
}

func TestSPA(t *testing.T) {
	h, _ := testServer(t, "", nil, nil)
	if rec := do(h, http.MethodGet, "/access", "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app") {
		t.Errorf("deep link = %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/assets/app-1.js", "", nil); !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Error("asset not immutable")
	}
}

func TestHostFailureIs502(t *testing.T) {
	fr := &fakeRunner{fn: func([]string) *dockerx.RunResult {
		return &dockerx.RunResult{ExitCode: 127, Stderr: "bash: /x/authelia-user-manager.sh: No such file or directory\n"}
	}}
	h, _ := testServer(t, "alice", []string{"admins"}, fr)
	if rec := do(h, http.MethodGet, "/api/users", "", nil); rec.Code != http.StatusBadGateway {
		t.Fatalf("missing script = %d %s", rec.Code, rec.Body)
	}
}
