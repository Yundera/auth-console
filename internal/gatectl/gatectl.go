// Package gatectl talks to this console's own AppShield gate's control API:
// ending sessions already in flight when an account is deleted or its password
// reset. Ported from settings-center-app's backend/auth/gateControl.ts.
//
// The control token is an HS256 JWT signed with the SAME secret the gate signs
// identity assertions with, but on the `appshield-control` audience. That split
// is the security property: assertions reach this backend on every request and
// may be logged, and without a separate audience each one would be a
// revocation credential. The gate also refuses a token living over 300s.
//
// Only this gate is reached. Other gates (maison, mesh-console, store apps)
// keep their sessions — the accepted v1 gap, see architecture.md §7.3.
package gatectl

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

const (
	audience = "appshield-control"
	issuer   = "appshield-backend"
	subject  = "auth-console-app"
	tokenTTL = 60 * time.Second
	timeout  = 4 * time.Second
)

// Selector picks the sessions to end. A session matching User or Sub is
// revoked; Except spares the caller's own session (resetting your own
// password must not log you out of the page you are doing it from).
type Selector struct {
	User   string   `json:"user,omitempty"`
	Sub    string   `json:"sub,omitempty"`
	All    bool     `json:"all,omitempty"`
	Except []string `json:"except,omitempty"`
}

type Client struct {
	BaseURL string
	Secret  []byte
	HTTP    *http.Client
	Now     func() time.Time
}

// Token mints a control token.
func (c Client) Token() string {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	t := now()
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	body, _ := json.Marshal(map[string]any{
		"iss": issuer, "aud": audience, "sub": subject,
		"iat": t.Unix(), "exp": t.Add(tokenTTL).Unix(),
	})
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	m := hmac.New(sha256.New, c.Secret)
	m.Write([]byte(in))
	return in + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Revoke ends the selected sessions and returns how many. It never fails the
// caller's action: the account change has already happened, and ok=false only
// means the handler should warn that old sessions may still be open.
func (c Client) Revoke(ctx context.Context, sel Selector) (revoked int, ok bool) {
	if len(c.Secret) == 0 {
		return 0, false
	}
	body, _ := json.Marshal(sel)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/nhl-auth/sessions/revoke", bytes.NewReader(body))
	if err != nil {
		return 0, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token())
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	res, err := hc.Do(req)
	if err != nil {
		log.Printf("session revocation failed: %v", err)
		return 0, false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Printf("session revocation: gate answered %d", res.StatusCode)
		return 0, false
	}
	var out struct {
		Revoked int `json:"revoked"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return out.Revoked, true
}
