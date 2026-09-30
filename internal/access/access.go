// Package access parses the host report produced by hostverb.AccessInfo: Linux
// accounts, their authorized_keys, and recent logins. The parsing is a port of
// settings-center-app's pages/api/admin/access-info.ts, kept behaviour-for-
// behaviour so both surfaces agree while they coexist.
package access

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	// AdminKeyComment marks the key the Yundera admin app (settings-center-app)
	// reaches the host with. Removing it breaks that app, so the console
	// refuses to on the dashboard account.
	AdminKeyComment = "local-admin-access"
	// UserKeyPrefix marks keys a person added for themselves — the lockout
	// guard counts these.
	UserKeyPrefix = "user-"
)

type Key struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Bits        *int   `json:"bits"`
	Comment     string `json:"comment"`
	IsAdminKey  bool   `json:"isAdminKey"`
	IsSupport   bool   `json:"isSupportKey"`
	IsUserKey   bool   `json:"isUserKey"`
}

type Login struct {
	Username string `json:"username"`
	Terminal string `json:"terminal"`
	From     string `json:"from"`
	Time     string `json:"time"`
	Duration string `json:"duration"`
}

type Account struct {
	Username       string  `json:"username"`
	UID            int     `json:"uid"`
	GID            int     `json:"gid"`
	Home           string  `json:"home"`
	Shell          string  `json:"shell"`
	IsSystem       bool    `json:"isSystem"`
	LastLoginTime  *string `json:"lastLoginTime"`
	LastLoginFrom  *string `json:"lastLoginFrom"`
	AuthorizedKeys []Key   `json:"authorizedKeys"`
	KeysError      *string `json:"authorizedKeysError"`
}

type Report struct {
	Accounts     []Account `json:"accounts"`
	RecentLogins []Login   `json:"recentLogins"`
}

// Parse turns the collect script's stdout into a report. supportFP tags the
// operator's support key; empty when unknown (FOSS, operator unreachable).
func Parse(stdout, supportFP string) Report {
	sections := splitSections(stdout)
	accounts := parsePasswd(sections["PASSWD"])
	logins := parseLast(sections["LAST"])
	keys := parseKeys(sections["KEYS"], supportFP)

	seen := map[string]bool{}
	for _, ev := range logins {
		if seen[ev.Username] {
			continue
		}
		seen[ev.Username] = true
		for i := range accounts {
			if accounts[i].Username == ev.Username {
				t, from := ev.Time, ev.From
				if from == "" {
					from = ev.Terminal
				}
				accounts[i].LastLoginTime, accounts[i].LastLoginFrom = &t, &from
			}
		}
	}
	for i := range accounts {
		if e, ok := keys[accounts[i].Username]; ok {
			accounts[i].AuthorizedKeys = e.keys
			accounts[i].KeysError = e.err
		}
	}
	if logins == nil {
		logins = []Login{}
	}
	return Report{Accounts: accounts, RecentLogins: logins}
}

var markerRe = regexp.MustCompile(`^===([A-Z]+)===$`)

func splitSections(stdout string) map[string]string {
	out := map[string]string{}
	current := ""
	var buf []string
	for _, line := range strings.Split(stdout, "\n") {
		if m := markerRe.FindStringSubmatch(line); m != nil {
			if current != "" {
				out[current] = strings.Join(buf, "\n")
			}
			current, buf = m[1], nil
		} else if current != "" {
			buf = append(buf, line)
		}
	}
	if current != "" {
		out[current] = strings.Join(buf, "\n")
	}
	return out
}

var noLoginShells = map[string]bool{"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true}

func parsePasswd(block string) []Account {
	out := []Account{}
	for _, line := range strings.Split(block, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) < 7 {
			continue
		}
		uid, err := strconv.Atoi(p[2])
		if err != nil {
			continue
		}
		gid, _ := strconv.Atoi(p[3])
		out = append(out, Account{
			Username: p[0], UID: uid, GID: gid, Home: p[5], Shell: p[6],
			IsSystem:       uid != 0 && (uid < 1000 || noLoginShells[p[6]]),
			AuthorizedKeys: []Key{},
		})
	}
	return out
}

var (
	wtmpRe   = regexp.MustCompile(`(?i)^wtmp begins`)
	rebootRe = regexp.MustCompile(`(?i)^reboot\s+system`)
)

// slice is JavaScript's String.prototype.slice over runes, for the fixed
// columns of `last -F -i -w`.
func slice(r []rune, from, to int) string {
	if from > len(r) {
		return ""
	}
	if to < 0 || to > len(r) {
		to = len(r)
	}
	return string(r[from:to])
}

func parseLast(block string) []Login {
	var out []Login
	for _, raw := range strings.Split(block, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if strings.TrimSpace(line) == "" || wtmpRe.MatchString(line) || rebootRe.MatchString(line) {
			continue
		}
		r := []rune(line)
		user := strings.TrimSpace(slice(r, 0, 8))
		if user == "" || user == "reboot" || user == "shutdown" {
			continue
		}
		rest := strings.TrimSpace(slice(r, 39, -1))
		t, d := rest, ""
		if i := strings.Index(rest, " - "); i >= 0 {
			t, d = strings.TrimSpace(rest[:i]), strings.TrimSpace(rest[i+3:])
		}
		out = append(out, Login{
			Username: user,
			Terminal: strings.TrimSpace(slice(r, 9, 21)),
			From:     strings.TrimSpace(slice(r, 22, 38)),
			Time:     t,
			Duration: d,
		})
	}
	return out
}

var (
	userRe = regexp.MustCompile(`^---USER:(.+)---$`)
	fpRe   = regexp.MustCompile(`^(\d+)\s+(\S+)\s+(.*)\s+\(([^)]+)\)\s*$`)
)

type fpEntry struct {
	typ, fp, comment string
	bits             *int
}

type rawEntry struct{ typ, comment string }

func parseFP(line string) *fpEntry {
	m := fpRe.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return nil
	}
	e := &fpEntry{typ: m[4], fp: m[2], comment: strings.TrimSpace(m[3])}
	if b, err := strconv.Atoi(m[1]); err == nil && b != 0 {
		e.bits = &b
	}
	return e
}

func parseRaw(line string) *rawEntry {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return nil
	}
	p := strings.Fields(t)
	if len(p) < 2 {
		return nil
	}
	return &rawEntry{typ: p[0], comment: strings.Join(p[2:], " ")}
}

type keysEntry struct {
	keys []Key
	err  *string
}

func parseKeys(block, supportFP string) map[string]keysEntry {
	out := map[string]keysEntry{}
	lines := strings.Split(block, "\n")
	for i := 0; i < len(lines); {
		m := userRe.FindStringSubmatch(lines[i])
		if m == nil {
			i++
			continue
		}
		user := m[1]
		i++
		var fpLines, rawLines []string
		for i < len(lines) && !userRe.MatchString(lines[i]) {
			switch lines[i] {
			case "FP_START":
				for i++; i < len(lines) && lines[i] != "FP_END"; i++ {
					fpLines = append(fpLines, lines[i])
				}
			case "RAW_START":
				for i++; i < len(lines) && lines[i] != "RAW_END"; i++ {
					rawLines = append(rawLines, lines[i])
				}
			}
			i++
		}
		var fps []fpEntry
		var raws []rawEntry
		for _, l := range fpLines {
			if e := parseFP(l); e != nil {
				fps = append(fps, *e)
			}
		}
		for _, l := range rawLines {
			if e := parseRaw(l); e != nil {
				raws = append(raws, *e)
			}
		}
		keys := []Key{}
		if len(fps) == len(raws) && len(fps) > 0 {
			for idx, f := range fps {
				comment := raws[idx].comment
				if comment == "" {
					comment = f.comment
				}
				keys = append(keys, Key{
					Type: f.typ, Fingerprint: f.fp, Bits: f.bits, Comment: comment,
					IsAdminKey: strings.Contains(comment, AdminKeyComment),
					IsSupport:  supportFP != "" && f.fp == supportFP,
					IsUserKey:  strings.HasPrefix(comment, UserKeyPrefix),
				})
			}
		} else {
			// Raw-only fallback: no fingerprint, so it can never be positively
			// matched to the support key, nor removed.
			for _, r := range raws {
				keys = append(keys, Key{
					Type: r.typ, Comment: r.comment,
					IsAdminKey: strings.Contains(r.comment, AdminKeyComment),
					IsUserKey:  strings.HasPrefix(r.comment, UserKeyPrefix),
				})
			}
		}
		var errp *string
		if len(raws) == 0 && len(rawLines) > 0 {
			s := "Could not parse authorized_keys"
			errp = &s
		}
		out[user] = keysEntry{keys: keys, err: errp}
	}
	return out
}
