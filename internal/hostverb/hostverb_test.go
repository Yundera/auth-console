package hostverb

import (
	"strings"
	"testing"
)

const scripts = Scripts("/DATA/AppData/yundera/template/scripts")

var hostile = []string{"", "-x", "a;b", "$(id)", "a`id`", "a\nb", "a b", "A", "../x", "a'b", strings.Repeat("a", 33)}

func TestUsers(t *testing.T) {
	v, err := scripts.UsersList()
	if err != nil || strings.Join(v.Argv, " ") != "bash /DATA/AppData/yundera/template/scripts/tools/authelia-user-manager.sh list" {
		t.Fatalf("list: %+v %v", v, err)
	}
	v, err = scripts.UsersAdd("alice", "  Alice Doe ", "alice@example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"add", "alice", "Alice Doe", "alice@example.com", "admins,users"}
	if got := v.Argv[2:]; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("add argv = %q", got)
	}
	v, _ = scripts.UsersAdd("bob", "Bob", "bob@example.com", false)
	if v.Argv[len(v.Argv)-1] != "users" {
		t.Fatalf("non-admin groups = %q", v.Argv)
	}
	for _, bad := range hostile {
		if _, err := scripts.UsersDelete(bad); err == nil {
			t.Errorf("delete accepted username %q", bad)
		}
		if _, err := scripts.UsersSetPassword(bad); err == nil {
			t.Errorf("set-password accepted username %q", bad)
		}
	}
	for _, bad := range []string{"", "no-at", "a@b", "a b@c.d", "a@b.c\nx"} {
		if _, err := scripts.UsersSetEmail("alice", bad); err == nil {
			t.Errorf("email %q accepted", bad)
		}
	}
	for _, bad := range []string{"", "   ", "x\ny", strings.Repeat("é", 65)} {
		if _, err := scripts.UsersAdd("alice", bad, "a@b.co", false); err == nil {
			t.Errorf("display name %q accepted", bad)
		}
	}
}

func TestRoots(t *testing.T) {
	for _, bad := range []string{"", "/", "relative", "/DATA/../etc", "/DATA/$(id)", "/DATA/a b"} {
		if _, err := Scripts(bad).UsersList(); err == nil {
			t.Errorf("scripts dir %q accepted", bad)
		}
		if _, err := scripts.SupportStatus(bad); err == nil {
			t.Errorf("host root %q accepted", bad)
		}
	}
}

func TestSupport(t *testing.T) {
	v, err := scripts.SupportStatus("/DATA/AppData/yundera")
	if err != nil {
		t.Fatal(err)
	}
	n := len(v.Argv)
	if v.Argv[1] != "-c" || v.Argv[2] != supportStatusScript || v.Argv[n-2] != "/DATA/AppData/yundera" || v.Argv[n-1] != string(scripts) {
		t.Fatalf("argv = %q", v.Argv)
	}
	on, _ := scripts.SupportSet(true)
	off, _ := scripts.SupportSet(false)
	if on.Argv[len(on.Argv)-1] != "enable" || off.Argv[len(off.Argv)-1] != "disable" {
		t.Fatalf("support set: %q %q", on.Argv, off.Argv)
	}
}

const edKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb0ZsYk2mT3OE9d3zVxj8pGQv5c7Qv1aJdR3r7hH0cK user-alice"

func TestAccessAddKey(t *testing.T) {
	v, err := AccessAddKey("alice", " "+edKey+"\r\n")
	if err != nil {
		t.Fatal(err)
	}
	// The script is fixed; values are positional args after $0.
	n := len(v.Argv)
	if v.Argv[2] != addKeyScript || v.Argv[n-2] != "alice" || v.Argv[n-1] != edKey {
		t.Fatalf("argv = %q", v.Argv)
	}
	for _, bad := range []string{
		"",
		"ssh-ed25519",
		"ssh-foo AAAA",
		"ssh-ed25519 AAA$A",
		edKey + "\n" + edKey,
		`command="rm -rf /" ` + edKey,
	} {
		if _, err := AccessAddKey("alice", bad); err == nil {
			t.Errorf("key %q accepted", bad)
		}
	}
	for _, bad := range hostile {
		if _, err := AccessAddKey(bad, edKey); err == nil {
			t.Errorf("username %q accepted", bad)
		}
	}
}

func TestAccessRemoveKey(t *testing.T) {
	fp := "SHA256:" + strings.Repeat("A", 43)
	v, err := AccessRemoveKey("admin", fp)
	if err != nil {
		t.Fatal(err)
	}
	n := len(v.Argv)
	if v.Argv[2] != removeKeyScript || v.Argv[n-2] != "admin" || v.Argv[n-1] != fp {
		t.Fatalf("argv = %q", v.Argv)
	}
	for _, bad := range []string{"", "SHA256:short", "SHA256:" + strings.Repeat("A", 43) + "'; id", "md5:xx"} {
		if _, err := AccessRemoveKey("admin", bad); err == nil {
			t.Errorf("fingerprint %q accepted", bad)
		}
	}
}
