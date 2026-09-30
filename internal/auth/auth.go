// Package auth verifies the identity the AppShield gate forwards.
//
// The gate is the only route in, but it is not the only thing on the pcs
// network: any app container can reach auth-console-app:8080 directly. So the
// plain X-Auth-Request-* headers prove nothing, and this package trusts only the
// HS256 X-AppShield-Assertion the gate signs with the secret it shares with us.
//
// Ported from mesh-console's internal/auth (itself from settings-center-app's
// backend/auth/gateIdentity.ts + session.ts).
// Verified by hand, like AppShield mints it (internal/identity/identity.go):
// one algorithm, one key — a JOSE library would be the largest dependency here.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	HeaderAssertion = "X-AppShield-Assertion"
	issuer          = "appshield"
	// leeway absorbs clock skew between the gate and this container. They run on
	// the same host, so it only needs to cover a second boundary.
	leeway = 5 * time.Second
)

// AdminGroups are the group names that grant access. Authelia's seeded group is
// `admins`; `admin` is accepted for parity with settings-center-app.
var AdminGroups = []string{"admins", "admin"}

type Identity struct {
	User   string   `json:"user"`
	Email  string   `json:"email,omitempty"`
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Method string   `json:"method"`
}

func (i Identity) IsAdmin() bool {
	for _, g := range i.Groups {
		for _, want := range AdminGroups {
			if g == want {
				return true
			}
		}
	}
	return false
}

type claims struct {
	Method string   `json:"method"`
	User   string   `json:"user"`
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
	Iss    string   `json:"iss"`
	Aud    string   `json:"aud"`
	Sub    string   `json:"sub"`
	Iat    int64    `json:"iat"`
	Exp    int64    `json:"exp"`
}

var (
	ErrNoSecret  = errors.New("assertion secret not configured")
	ErrMalformed = errors.New("malformed assertion")
	ErrSignature = errors.New("bad assertion signature")
	ErrClaims    = errors.New("assertion claims rejected")
)

// Verify checks tok and returns the identity it carries. Every check is
// load-bearing: the alg pin stops an "alg":"none" downgrade, iss/aud stop a
// token minted for another app (same secret reused) from being replayed here,
// and exp bounds a leaked token to the gate's ~60s TTL.
func Verify(tok string, secret []byte, audience string, now time.Time) (Identity, error) {
	if len(secret) == 0 {
		return Identity{}, ErrNoSecret
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Identity{}, ErrMalformed
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil || hdr.Alg != "HS256" {
		return Identity{}, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, ErrMalformed
	}
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, m.Sum(nil)) {
		return Identity{}, ErrSignature
	}
	var c claims
	if err := decodeSegment(parts[1], &c); err != nil {
		return Identity{}, ErrMalformed
	}
	if c.Iss != issuer || c.Aud != audience || c.Method == "" {
		return Identity{}, ErrClaims
	}
	if c.Exp == 0 || now.After(time.Unix(c.Exp, 0).Add(leeway)) {
		return Identity{}, ErrClaims
	}
	if c.Iat != 0 && time.Unix(c.Iat, 0).After(now.Add(leeway)) {
		return Identity{}, ErrClaims
	}
	user := c.User
	if user == "" {
		user = c.Sub
	}
	return Identity{User: user, Email: c.Email, Name: c.Name, Groups: c.Groups, Method: c.Method}, nil
}

func decodeSegment(seg string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

type ctxKey struct{}

// FromContext returns the identity RequireUser attached to the request.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// Authenticator turns a request into an identity.
type Authenticator struct {
	Secret   []byte
	Audience string
	// Dev, when non-nil, is returned for every request. The caller must only
	// set it outside production (see config.DevIdentity).
	Dev *Identity
	Now func() time.Time
}

func (a Authenticator) Identify(r *http.Request) (Identity, error) {
	if a.Dev != nil {
		return *a.Dev, nil
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	tok := strings.TrimSpace(r.Header.Get(HeaderAssertion))
	if tok == "" {
		if len(a.Secret) == 0 {
			return Identity{}, ErrNoSecret
		}
		return Identity{}, ErrMalformed
	}
	return Verify(tok, a.Secret, a.Audience, now())
}

// machineMethods are the gate's non-interactive auth methods (a static hash, an
// OAuth client). This console is for people: an account change must be traceable
// to someone who logged in.
var machineMethods = map[string]bool{"hash": true, "oauth": true}

// RequireUser answers 401 unless the request carries a valid assertion for a
// person. Unlike mesh-console the gate does NOT enforce a group here: every
// signed-in user may reach their own Account page. Admin-only routes add
// RequireAdmin on top.
func (a Authenticator) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := a.Identify(r)
		if err != nil || machineMethods[id.Method] {
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

// RequireAdmin must run after RequireUser. It answers 403 for an identity that
// is not in an admin group. Hiding a section in the UI is cosmetic; this is the
// enforcement.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := FromContext(r.Context())
		if !ok {
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if !id.IsAdmin() {
			writeErr(w, http.StatusForbidden, "admin group required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
