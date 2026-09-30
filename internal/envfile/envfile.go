// Package envfile reads the platform .env the way the templates' scripts do:
// line by line, never sourced.
//
// It is read from disk on every request rather than taken from this container's
// environment. The container env is a snapshot from its last recreate; the file
// is what the self-check and the next `docker compose up` will actually use —
// LOCAL_ADMIN_USER, for one, is written by `claim` long after this container
// started.
package envfile

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type Env map[string]string

// Load parses ${dir}/.env.
func Load(dir string) (Env, error) {
	f, err := os.Open(filepath.Join(dir, ".env"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	env := Env{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		k, v, ok := ParseLine(sc.Text())
		if ok {
			env[k] = v
		}
	}
	return env, sc.Err()
}

// ParseLine handles KEY=value, optional `export `, surrounding quotes, and
// skips comments and blanks.
func ParseLine(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	line = strings.TrimPrefix(line, "export ")
	k, v, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	k = strings.TrimSpace(k)
	if k == "" {
		return "", "", false
	}
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		v = v[1 : len(v)-1]
	}
	return k, v, true
}

// Get returns the first non-empty value among keys.
func (e Env) Get(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(e[k]); v != "" {
			return v
		}
	}
	return ""
}
