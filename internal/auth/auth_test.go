package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var (
	secret = []byte("test-secret-test-secret-test-secret")
	now    = time.Unix(1_800_000_000, 0)
)

func mint(t *testing.T, key []byte, alg string, c claims) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	body, _ := json.Marshal(c)
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func good() claims {
	return claims{
		Method: "oidc", User: "alice", Groups: []string{"users", "admins"},
		Iss: "appshield", Aud: "auth-console", Sub: "alice",
		Iat: now.Unix(), Exp: now.Unix() + 60,
	}
}

func TestVerify(t *testing.T) {
	expired := good()
	expired.Exp = now.Unix() - 60
	wrongAud := good()
	wrongAud.Aud = "admin"
	wrongIss := good()
	wrongIss.Iss = "someone"
	future := good()
	future.Iat = now.Unix() + 600
	noMethod := good()
	noMethod.Method = ""

	cases := []struct {
		name string
		tok  string
		key  []byte
		want error
	}{
		{"valid", mint(t, secret, "HS256", good()), secret, nil},
		{"expired", mint(t, secret, "HS256", expired), secret, ErrClaims},
		{"wrong audience", mint(t, secret, "HS256", wrongAud), secret, ErrClaims},
		{"wrong issuer", mint(t, secret, "HS256", wrongIss), secret, ErrClaims},
		{"issued in the future", mint(t, secret, "HS256", future), secret, ErrClaims},
		{"no method", mint(t, secret, "HS256", noMethod), secret, ErrClaims},
		{"wrong key", mint(t, []byte("other"), "HS256", good()), secret, ErrSignature},
		{"alg none", mint(t, secret, "none", good()), secret, ErrMalformed},
		{"garbage", "a.b", secret, ErrMalformed},
		{"no secret", mint(t, secret, "HS256", good()), nil, ErrNoSecret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := Verify(tc.tok, tc.key, "auth-console", now)
			if err != tc.want {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want == nil && id.User != "alice" {
				t.Fatalf("user = %q", id.User)
			}
		})
	}
}

func TestRequireUserAndAdmin(t *testing.T) {
	a := Authenticator{Secret: secret, Audience: "auth-console", Now: func() time.Time { return now }}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := FromContext(r.Context()); !ok {
			t.Error("identity missing from context")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	userOnly := a.RequireUser(ok)
	adminOnly := a.RequireUser(RequireAdmin(ok))

	nonAdmin := good()
	nonAdmin.Groups = []string{"users"}
	machine := good()
	machine.Method = "hash"

	cases := []struct {
		name      string
		headers   map[string]string
		wantUser  int
		wantAdmin int
	}{
		{"admin", map[string]string{HeaderAssertion: mint(t, secret, "HS256", good())}, http.StatusNoContent, http.StatusNoContent},
		{"non-admin", map[string]string{HeaderAssertion: mint(t, secret, "HS256", nonAdmin)}, http.StatusNoContent, http.StatusForbidden},
		{"machine identity", map[string]string{HeaderAssertion: mint(t, secret, "HS256", machine)}, http.StatusUnauthorized, http.StatusUnauthorized},
		{"no assertion", nil, http.StatusUnauthorized, http.StatusUnauthorized},
		// The unsigned headers a neighbour container could forge prove nothing.
		{"forged plain headers", map[string]string{"X-Auth-Request-User": "alice", "Remote-Groups": "admins"}, http.StatusUnauthorized, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range []struct {
				h    http.Handler
				want int
			}{{userOnly, tc.wantUser}, {adminOnly, tc.wantAdmin}} {
				req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
				for k, v := range tc.headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()
				c.h.ServeHTTP(rec, req)
				if rec.Code != c.want {
					t.Fatalf("status = %d, want %d", rec.Code, c.want)
				}
			}
		})
	}
}

func TestNoSecretFailsClosed(t *testing.T) {
	a := Authenticator{Audience: "auth-console"}
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.Header.Set(HeaderAssertion, mint(t, secret, "HS256", good()))
	rec := httptest.NewRecorder()
	a.RequireUser(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler reached without a secret")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}
