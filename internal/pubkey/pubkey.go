// Package pubkey fetches the SSH public key named by an Access deep link
// (`?account=&pubkeyUrl=`), for the consent screen. Ported from
// settings-center-app's pages/api/admin/access-fetch-pubkey.ts, with the SSRF
// check moved into the dialer.
//
// The TS version resolved the hostname, checked the addresses, then let fetch()
// resolve it again — a DNS-rebinding window. Here the check runs in
// net.Dialer.Control on the address actually being dialled, so there is no
// second resolution to race. Its timeout also covers the body, which the TS
// one stopped counting once headers arrived.
package pubkey

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/yundera/auth-console/internal/hostverb"
)

const (
	Timeout  = 10 * time.Second
	MaxBytes = 64 * 1024
)

// Trust grades a fetched key for the consent screen: "trusted" when the host is
// one the operator vouches for, "tls-verified" otherwise (it did come from that
// host over verified TLS, which says nothing about who controls it).
type Result struct {
	URL         string `json:"url"`
	Hostname    string `json:"hostname"`
	Trusted     bool   `json:"trusted"`
	Type        string `json:"type"`
	PublicKey   string `json:"publicKey"`
	Comment     string `json:"comment"`
	Fingerprint string `json:"fingerprint"`
}

// BadRequest is the caller's fault (400); anything else is the remote's (502).
type BadRequest struct{ Msg string }

func (e BadRequest) Error() string { return e.Msg }

var blocked = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// IsPrivate reports whether addr must not be dialled.
func IsPrivate(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range blocked {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

var errPrivate = errors.New("URL resolves to a private/loopback address")

// Fetcher's zero value is the production client; tests replace Client.
type Fetcher struct {
	Client          *http.Client
	TrustedSuffixes []string
	// allowLiteralPrivate lets tests reach an httptest server on 127.0.0.1.
	// The dialer check (NewClient) is the real guard and has no such switch.
	allowLiteralPrivate bool
}

func NewClient() *http.Client {
	d := &net.Dialer{
		Timeout: Timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || IsPrivate(ip) {
				return errPrivate
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: Timeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         d.DialContext,
			TLSHandshakeTimeout: Timeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not followed")
		},
	}
}

func (f Fetcher) Fetch(ctx context.Context, raw string) (*Result, error) {
	if raw == "" {
		return nil, BadRequest{"Missing url query parameter"}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, BadRequest{"Malformed URL"}
	}
	if u.Scheme != "https" {
		return nil, BadRequest{"Only https:// URLs are accepted"}
	}
	if u.User != nil {
		return nil, BadRequest{"URLs with embedded credentials are not accepted"}
	}
	host := strings.ToLower(u.Hostname())
	if ip, err := netip.ParseAddr(host); err == nil && IsPrivate(ip) && !f.allowLiteralPrivate {
		return nil, BadRequest{"URL points to a private/loopback address."}
	}

	c := f.Client
	if c == nil {
		c = NewClient()
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, BadRequest{"Malformed URL"}
	}
	req.Header.Set("Accept", "text/plain, application/json;q=0.9, */*;q=0.5")
	res, err := c.Do(req)
	if err != nil {
		if errors.Is(err, errPrivate) {
			return nil, BadRequest{errPrivate.Error() + "."}
		}
		return nil, fmt.Errorf("Failed to reach %s: %v", host, err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("%s returned HTTP %d", host, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("Failed to read response: %v", err)
	}
	if len(body) > MaxBytes {
		return nil, fmt.Errorf("Response from %s exceeded %d bytes", host, MaxBytes)
	}
	key, ok := Extract(string(body))
	if !ok {
		return nil, fmt.Errorf("%s did not return a recognizable SSH public key", host)
	}
	parts := strings.Fields(key)
	return &Result{
		URL:         u.String(),
		Hostname:    host,
		Trusted:     f.trusted(host),
		Type:        parts[0],
		PublicKey:   key,
		Comment:     strings.Join(parts[2:], " "),
		Fingerprint: Fingerprint(parts[1]),
	}, nil
}

func (f Fetcher) trusted(host string) bool {
	for _, s := range f.TrustedSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// Extract finds the key in a response body: the orchestrator's JSON shape
// ({publicKey | public_key | key | sshKey | ssh_key}) first, then the first
// plain-text line that is a valid key.
func Extract(body string) (string, bool) {
	t := strings.TrimSpace(body)
	if strings.HasPrefix(t, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(t), &m) == nil {
			for _, k := range []string{"publicKey", "public_key", "key", "sshKey", "ssh_key"} {
				if s, ok := m[k].(string); ok && s != "" {
					if key, err := hostverb.NormalizePublicKey(s); err == nil {
						return key, true
					}
					break
				}
			}
		}
	}
	for _, line := range strings.Split(t, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if key, err := hostverb.NormalizePublicKey(line); err == nil {
			return key, true
		}
	}
	return "", false
}

// Fingerprint is OpenSSH's SHA256 fingerprint of a key's base64 blob.
func Fingerprint(b64 string) string {
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}
