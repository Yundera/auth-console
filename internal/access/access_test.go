package access

import "testing"

const fixture = `noise before the first marker
===PASSWD===
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
admin:x:1000:1000:,,,:/home/admin:/bin/bash
svc:x:1001:1001::/home/svc:/usr/sbin/nologin
broken line
===LAST===
admin    pts/0        203.0.113.7      Tue Sep 30 10:00:00 2026 - Tue Sep 30 11:00:00 2026  (01:00)
admin    pts/1        198.51.100.2     Mon Sep 29 09:00:00 2026 - Mon Sep 29 09:30:00 2026  (00:30)
reboot   system boot  6.8.0            Mon Sep 29 08:00:00 2026   still running

wtmp begins Mon Sep  1 00:00:00 2026
===KEYS===
---USER:admin---
FP_START
256 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA local-admin-access (ED25519)
256 SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB pcs-support (ED25519)
3072 SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC user-alice laptop (RSA)
FP_END
RAW_START
ssh-ed25519 AAAA local-admin-access
# a comment
ssh-ed25519 BBBB pcs-support
ssh-rsa CCCC user-alice laptop
RAW_END
---USER:root---
FP_START
FP_END
RAW_START
garbage
RAW_END
===END===
`

func TestParse(t *testing.T) {
	r := Parse(fixture, "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	if len(r.Accounts) != 4 {
		t.Fatalf("accounts = %d", len(r.Accounts))
	}
	byName := map[string]Account{}
	for _, a := range r.Accounts {
		byName[a.Username] = a
	}
	if byName["root"].IsSystem || !byName["daemon"].IsSystem || byName["admin"].IsSystem || !byName["svc"].IsSystem {
		t.Errorf("isSystem wrong: %+v", r.Accounts)
	}

	if len(r.RecentLogins) != 2 {
		t.Fatalf("logins = %+v", r.RecentLogins)
	}
	l := r.RecentLogins[0]
	if l.Username != "admin" || l.Terminal != "pts/0" || l.From != "203.0.113.7" || l.Time != "Tue Sep 30 10:00:00 2026" {
		t.Errorf("login = %+v", l)
	}
	admin := byName["admin"]
	if admin.LastLoginFrom == nil || *admin.LastLoginFrom != "203.0.113.7" {
		t.Errorf("last login from = %v", admin.LastLoginFrom)
	}

	keys := admin.AuthorizedKeys
	if len(keys) != 3 {
		t.Fatalf("keys = %+v", keys)
	}
	if !keys[0].IsAdminKey || keys[0].IsUserKey || keys[0].IsSupport {
		t.Errorf("admin key tags = %+v", keys[0])
	}
	if !keys[1].IsSupport {
		t.Errorf("support key not tagged: %+v", keys[1])
	}
	if !keys[2].IsUserKey || keys[2].Comment != "user-alice laptop" || keys[2].Bits == nil || *keys[2].Bits != 3072 {
		t.Errorf("user key = %+v", keys[2])
	}

	root := byName["root"]
	if root.KeysError == nil || len(root.AuthorizedKeys) != 0 {
		t.Errorf("root keys = %+v err %v", root.AuthorizedKeys, root.KeysError)
	}
	if byName["svc"].AuthorizedKeys == nil {
		t.Error("keys must marshal as [] not null")
	}
}
