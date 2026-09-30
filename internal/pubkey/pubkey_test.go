package pubkey

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb0ZsYk2mT3OE9d3zVxj8pGQv5c7Qv1aJdR3r7hH0cK pcs-support"

func TestIsPrivate(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "198.18.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1"} {
		if !IsPrivate(netip.MustParseAddr(s)) {
			t.Errorf("%s not blocked", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700::1111"} {
		if IsPrivate(netip.MustParseAddr(s)) {
			t.Errorf("%s blocked", s)
		}
	}
}

func TestFetchValidation(t *testing.T) {
	f := Fetcher{}
	for _, raw := range []string{"", "::", "http://example.com/k", "https://u:p@example.com/k", "https://127.0.0.1/k", "https://[::1]/k", "https://10.0.0.1/k"} {
		_, err := f.Fetch(context.Background(), raw)
		var br BadRequest
		if !errors.As(err, &br) {
			t.Errorf("%q: err = %v, want BadRequest", raw, err)
		}
	}
}

// The production dialer refuses loopback, so the httptest TLS server (on
// 127.0.0.1) is unreachable through it — which is itself the rebinding test.
func TestDialerRefusesLoopback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(key))
	}))
	defer srv.Close()
	// localhost resolves to loopback: the check happens at dial time.
	u := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	_, err := Fetcher{}.Fetch(context.Background(), u)
	var br BadRequest
	if !errors.As(err, &br) {
		t.Fatalf("err = %v, want private-address refusal", err)
	}
}

func TestFetchBodies(t *testing.T) {
	var body string
	status := 200
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/key", http.StatusFound)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	// The test server's client trusts its cert; loopback is allowed only here.
	f := Fetcher{Client: srv.Client(), TrustedSuffixes: []string{"127.0.0.1"}, allowLiteralPrivate: true}
	f.Client.CheckRedirect = NewClient().CheckRedirect

	body = `{"algorithm":"ssh-ed25519","publicKey":"` + key + `"}`
	r, err := f.Fetch(context.Background(), srv.URL+"/key")
	if err != nil {
		t.Fatal(err)
	}
	if r.PublicKey != key || r.Comment != "pcs-support" || !strings.HasPrefix(r.Fingerprint, "SHA256:") || !r.Trusted {
		t.Fatalf("result = %+v", r)
	}

	body = "# header\n" + key + "\n"
	if r, err := f.Fetch(context.Background(), srv.URL+"/key"); err != nil || r.PublicKey != key {
		t.Fatalf("plain text: %+v %v", r, err)
	}

	body = "not a key"
	if _, err := f.Fetch(context.Background(), srv.URL+"/key"); err == nil {
		t.Error("garbage accepted")
	}

	body = strings.Repeat("x", MaxBytes+10)
	if _, err := f.Fetch(context.Background(), srv.URL+"/key"); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("oversize: %v", err)
	}

	body, status = key, 404
	if _, err := f.Fetch(context.Background(), srv.URL+"/key"); err == nil {
		t.Error("404 accepted")
	}

	status = 200
	if _, err := f.Fetch(context.Background(), srv.URL+"/redirect"); err == nil {
		t.Error("redirect followed")
	}
}
