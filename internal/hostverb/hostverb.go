// Package hostverb is the complete list of things auth-console can make the
// host do. There is no generic "run a command" path: every verb is a fixed
// argv built here, user input only ever lands in a validated positional
// argument, and nothing is interpolated into a shell string.
//
// The argv runs inside the host's namespaces, as root (see dockerx.RunOnHost),
// so paths are HOST paths — HOST_ROOT, not the /host-root mount this container
// reads. Account changes go through the template's own authelia-user-manager.sh
// (flock, atomic yq write, argon2 via the Authelia image): this console never
// writes users_database.yml itself.
package hostverb

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

type Verb struct {
	Name string
	Argv []string
}

var (
	rootRe = regexp.MustCompile(`^/[a-zA-Z0-9/_.-]+$`)
	// UsernameRe is the Linux/Authelia username shape shared by the template
	// script and settings-center-app. It also rules out every shell and yq
	// metacharacter.
	UsernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	emailRe    = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	ctrlRe     = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	// KeyTypeRe / keyBodyRe are the OpenSSH public-key types we accept.
	KeyTypeRe   = regexp.MustCompile(`^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$`)
	keyBodyRe   = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
	fingerprint = regexp.MustCompile(`^(SHA256:[A-Za-z0-9+/]{43}=*|MD5:(?:[0-9a-f]{2}:){15}[0-9a-f]{2})$`)
)

const maxDisplayName = 64

// ---- validation ------------------------------------------------------------

func CheckRoot(p string) error {
	if !rootRe.MatchString(p) || path.Clean(p) != p || p == "/" {
		return errors.New("invalid host path")
	}
	return nil
}

func CheckUsername(u string) error {
	if u == "" {
		return errors.New("Username is required")
	}
	if !UsernameRe.MatchString(u) {
		return errors.New(`Username must start with a lowercase letter or underscore and contain only lowercase letters, digits, "-" or "_" (max 32 characters)`)
	}
	return nil
}

func CheckEmail(e string) error {
	if e == "" {
		return errors.New("Email is required")
	}
	if !emailRe.MatchString(e) || ctrlRe.MatchString(e) {
		return errors.New("Email is not a valid address")
	}
	return nil
}

func CheckDisplayName(d string) error {
	if strings.TrimSpace(d) == "" {
		return errors.New("Display name is required")
	}
	if len([]rune(d)) > maxDisplayName {
		return fmt.Errorf("Display name must be %d characters or fewer", maxDisplayName)
	}
	if ctrlRe.MatchString(d) {
		return errors.New("Display name contains control characters")
	}
	return nil
}

func CheckFingerprint(fp string) error {
	if !fingerprint.MatchString(fp) {
		return errors.New("Invalid fingerprint")
	}
	return nil
}

// NormalizePublicKey validates one OpenSSH public-key line and returns it
// trimmed. Only one key per call: a newline would smuggle a second line into
// authorized_keys (with options such as command= in front of it).
func NormalizePublicKey(k string) (string, error) {
	k = strings.TrimSpace(strings.ReplaceAll(k, "\r", ""))
	if k == "" {
		return "", errors.New("Public key is empty")
	}
	if strings.Contains(k, "\n") {
		return "", errors.New("Only a single key may be added at a time")
	}
	parts := strings.Fields(k)
	if len(parts) < 2 {
		return "", errors.New("Public key must have at least <type> <base64>")
	}
	if !KeyTypeRe.MatchString(parts[0]) {
		return "", fmt.Errorf("Unsupported key type: %s", parts[0])
	}
	if !keyBodyRe.MatchString(parts[1]) {
		return "", errors.New("Invalid base64 in public key body")
	}
	if ctrlRe.MatchString(k) {
		return "", errors.New("Public key contains control characters")
	}
	return k, nil
}

// ---- Authelia accounts (authelia-user-manager.sh) ----------------------------

// Scripts is the template's scripts directory as the host sees it:
// ${HOST_ROOT}/template/scripts on a Yundera PCS, ${HOST_ROOT}/scripts on a
// mesh box. The caller decides which exists (it can see the mount).
type Scripts string

func (s Scripts) userManager(args ...string) (Verb, error) {
	if err := CheckRoot(string(s)); err != nil {
		return Verb{}, err
	}
	return Verb{
		Name: "users-" + args[0],
		Argv: append([]string{"bash", path.Join(string(s), "tools", "authelia-user-manager.sh")}, args...),
	}, nil
}

func (s Scripts) UsersList() (Verb, error) { return s.userManager("list") }

func (s Scripts) UsersAdd(username, displayName, email string, admin bool) (Verb, error) {
	if err := CheckUsername(username); err != nil {
		return Verb{}, err
	}
	displayName = strings.TrimSpace(displayName)
	if err := CheckDisplayName(displayName); err != nil {
		return Verb{}, err
	}
	if err := CheckEmail(email); err != nil {
		return Verb{}, err
	}
	groups := "users"
	if admin {
		groups = "admins,users"
	}
	return s.userManager("add", username, displayName, email, groups)
}

func (s Scripts) UsersDelete(username string) (Verb, error) {
	if err := CheckUsername(username); err != nil {
		return Verb{}, err
	}
	return s.userManager("delete", username)
}

func (s Scripts) UsersSetPassword(username string) (Verb, error) {
	if err := CheckUsername(username); err != nil {
		return Verb{}, err
	}
	return s.userManager("set-password", username)
}

func (s Scripts) UsersSetEmail(username, email string) (Verb, error) {
	if err := CheckUsername(username); err != nil {
		return Verb{}, err
	}
	if err := CheckEmail(email); err != nil {
		return Verb{}, err
	}
	return s.userManager("set-email", username, email)
}

// OnboardingStatus is Yundera-only (tools/onboarding.sh). Read-only by
// decision: reset is terminal-only, and claiming stays on the command line.
func (s Scripts) OnboardingStatus() (Verb, error) {
	if err := CheckRoot(string(s)); err != nil {
		return Verb{}, err
	}
	return Verb{Name: "onboarding-status", Argv: []string{"bash", path.Join(string(s), "tools", "onboarding.sh"), "status"}}, nil
}

// ---- support key (Yundera only) ---------------------------------------------

// supportStatusScript prints ENSURE=<raw ENSURE_SUPPORT_KEY> and one FP=<fp>
// line per key in admin's authorized_keys. $1 = platform root, $2 = scripts.
const supportStatusScript = `set -u
root="$1"; scripts="$2"
echo "ENSURE=$(bash "$scripts/tools/env-file-manager.sh" get ENSURE_SUPPORT_KEY "$root/.pcs.env" 2>/dev/null || true)"
home=$(getent passwd admin | cut -d: -f6)
ak="$home/.ssh/authorized_keys"
if [ -n "$home" ] && [ -f "$ak" ]; then
  ssh-keygen -lf "$ak" 2>/dev/null | awk '{print "FP=" $2}'
fi
exit 0
`

func (s Scripts) SupportStatus(hostRoot string) (Verb, error) {
	if err := CheckRoot(hostRoot); err != nil {
		return Verb{}, err
	}
	if err := CheckRoot(string(s)); err != nil {
		return Verb{}, err
	}
	return Verb{Name: "support-status", Argv: []string{"bash", "-c", supportStatusScript, "support-status", hostRoot, string(s)}}, nil
}

// SupportSet flips ENSURE_SUPPORT_KEY through the template's own feature
// script, which also adds or removes the key. It answers {"enabled": bool}.
func (s Scripts) SupportSet(enable bool) (Verb, error) {
	if err := CheckRoot(string(s)); err != nil {
		return Verb{}, err
	}
	action := "disable"
	if enable {
		action = "enable"
	}
	return Verb{Name: "support-" + action, Argv: []string{"bash", path.Join(string(s), "tools", "feature-support-key.sh"), action}}, nil
}

// ---- host SSH access ---------------------------------------------------------

// accessInfoScript is settings-center-app's access-info collect script, minus
// `sudo -n`: the runner already is root in the host's namespaces. Its section
// markers are what internal/access parses.
const accessInfoScript = `echo '===PASSWD==='
getent passwd
echo '===LAST==='
last -F -i -w -n 50 2>/dev/null | head -n 50 || true
echo '===KEYS==='
getent passwd | while IFS=: read -r name _ uid _ _ home shell; do
  if [ -z "$home" ] || [ ! -d "$home" ]; then continue; fi
  ak="$home/.ssh/authorized_keys"
  if ! test -f "$ak"; then continue; fi
  echo "---USER:$name---"
  echo "FP_START"
  ssh-keygen -lf "$ak" 2>/dev/null || true
  echo "FP_END"
  echo "RAW_START"
  cat "$ak" 2>/dev/null || true
  echo "RAW_END"
done
echo '===END==='
`

func AccessInfo() Verb {
	return Verb{Name: "access-info", Argv: []string{"bash", "-c", accessInfoScript, "access-info"}}
}

// Exit codes shared by the key scripts, mapped to 404 / 409 by the handler.
const (
	ExitUserNotFound = 2
	ExitHomeMissing  = 3
	ExitUnsafePath   = 4
)

// addKeyScript appends one key (already validated) to the user's
// authorized_keys. It refuses a symlinked ~/.ssh or authorized_keys: the user
// owns their home, and root writing through a link they planted would edit an
// arbitrary file. It also terminates a last line that lacks a newline, which
// would otherwise glue the new key onto the previous one.
const addKeyScript = `set -eu
user="$1"; key="$2"
home=$(getent passwd "$user" | cut -d: -f6)
if [ -z "$home" ]; then echo USER_NOT_FOUND; exit 2; fi
if [ ! -d "$home" ]; then echo HOME_MISSING; exit 3; fi
dir="$home/.ssh"; ak="$dir/authorized_keys"
if [ -L "$dir" ] || [ -L "$ak" ]; then echo UNSAFE_PATH; exit 4; fi
mkdir -p "$dir"
chmod 700 "$dir"
touch "$ak"
if grep -qxF -- "$key" "$ak" 2>/dev/null; then
  echo ALREADY_PRESENT
else
  if [ -s "$ak" ] && [ -n "$(tail -c1 "$ak")" ]; then echo >> "$ak"; fi
  printf '%s\n' "$key" >> "$ak"
  echo ADDED
fi
chmod 600 "$ak"
chown -R "$user": "$dir" 2>/dev/null || true
`

func AccessAddKey(username, publicKey string) (Verb, error) {
	if err := CheckUsername(username); err != nil {
		return Verb{}, err
	}
	k, err := NormalizePublicKey(publicKey)
	if err != nil {
		return Verb{}, err
	}
	return Verb{Name: "access-add-key", Argv: []string{"bash", "-c", addKeyScript, "access-add-key", username, k}}, nil
}

// removeKeyScript drops every line whose fingerprint is $2 (comments and
// blank lines are kept as they are) and writes the file back in place, so its
// owner and mode survive.
const removeKeyScript = `set -eu
user="$1"; target="$2"
home=$(getent passwd "$user" | cut -d: -f6)
if [ -z "$home" ]; then echo USER_NOT_FOUND; exit 2; fi
ak="$home/.ssh/authorized_keys"
if [ -L "$home/.ssh" ] || [ -L "$ak" ]; then echo UNSAFE_PATH; exit 4; fi
if [ ! -f "$ak" ]; then echo NOT_FOUND; exit 0; fi
tmp=$(mktemp); one=$(mktemp)
trap 'rm -f "$tmp" "$one"' EXIT
removed=0
while IFS= read -r line || [ -n "$line" ]; do
  trimmed=$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
  if [ -z "$trimmed" ] || [ "${trimmed#\#}" != "$trimmed" ]; then
    printf '%s\n' "$line" >> "$tmp"
    continue
  fi
  printf '%s\n' "$line" > "$one"
  fp=$(ssh-keygen -lf "$one" 2>/dev/null | awk '{print $2}')
  if [ "$fp" = "$target" ]; then
    removed=$((removed+1))
  else
    printf '%s\n' "$line" >> "$tmp"
  fi
done < "$ak"
if [ "$removed" -eq 0 ]; then echo NOT_FOUND; exit 0; fi
cat "$tmp" > "$ak"
echo "REMOVED:$removed"
`

func AccessRemoveKey(username, fp string) (Verb, error) {
	if err := CheckUsername(username); err != nil {
		return Verb{}, err
	}
	if err := CheckFingerprint(fp); err != nil {
		return Verb{}, err
	}
	return Verb{Name: "access-remove-key", Argv: []string{"bash", "-c", removeKeyScript, "access-remove-key", username, fp}}, nil
}
