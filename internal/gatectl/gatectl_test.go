package gatectl

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRevoke(t *testing.T) {
	secret := []byte("s3cret-s3cret-s3cret")
	now := time.Unix(1_800_000_000, 0)
	var got Selector
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nhl-auth/sessions/revoke" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(tok, ".")
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(parts[0] + "." + parts[1]))
		if base64.RawURLEncoding.EncodeToString(m.Sum(nil)) != parts[2] {
			t.Error("bad signature")
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		if c["aud"] != "appshield-control" || c["iss"] != "appshield-backend" || c["sub"] != "auth-console-app" {
			t.Errorf("claims = %v", c)
		}
		if exp, iat := c["exp"].(float64), c["iat"].(float64); exp-iat > 300 || exp <= iat {
			t.Errorf("lifetime %v..%v", iat, exp)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"revoked":2}`))
	}))
	defer gate.Close()

	c := Client{BaseURL: gate.URL, Secret: secret, Now: func() time.Time { return now }}
	n, ok := c.Revoke(context.Background(), Selector{User: "bob", Except: []string{"sid1"}})
	if !ok || n != 2 {
		t.Fatalf("revoke = %d %v", n, ok)
	}
	if got.User != "bob" || len(got.Except) != 1 || got.All {
		t.Fatalf("selector = %+v", got)
	}

	if _, ok := (Client{BaseURL: gate.URL}).Revoke(context.Background(), Selector{All: true}); ok {
		t.Error("revoked without a secret")
	}
	if _, ok := (Client{BaseURL: "http://127.0.0.1:1", Secret: secret}).Revoke(context.Background(), Selector{All: true}); ok {
		t.Error("unreachable gate reported ok")
	}
}
