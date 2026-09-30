// Package config reads the console's settings from its environment. Everything
// that can change while the container runs (DOMAIN, LOCAL_ADMIN_USER, ...) is
// read from the platform .env per request instead — see internal/envfile.
package config

import (
	"os"
	"strings"
)

type Config struct {
	// Addr is the listen address.
	Addr string

	// AssertionSecret verifies the gate's X-AppShield-Assertion and signs the
	// control tokens sent back to it (session revocation). Empty = every API
	// request is refused.
	AssertionSecret string
	// AssertionAudience must equal the gate's APP_NAME (derived from its
	// hostname, `auth-console`).
	AssertionAudience string
	// GateURL is where the gate's control API answers (sessions/revoke).
	GateURL string

	// DevIdentity is `user[:group,group]`; honoured only when Env is
	// "development" and no secret is set.
	DevIdentity string
	Env         string

	// HostRoot is the platform root as the HOST sees it
	// (/DATA/AppData/yundera, /DATA/AppData/mesh). Host verbs run in the host's
	// mount namespace, so every path they get is built from this.
	HostRoot string
	// HostScripts is the template's scripts directory as the host sees it
	// (${HOST_ROOT}/template/scripts on Yundera, ${HOST_ROOT}/scripts on a mesh
	// box). Empty = detected: template/scripts when it exists, else scripts.
	// Must be under HostRoot, so it can be seen through HostRootMount.
	HostScripts string
	// HostRootMount is the same directory mounted read-only here: the .env is
	// read and the host's capabilities (which scripts exist) are detected
	// through it. Never written.
	HostRootMount string

	// SelfContainer / RunnerImage: how the runner image is found.
	SelfContainer string
	RunnerImage   string

	// OperatorAPI enables the Yundera-only pieces: the support-key tag and the
	// support toggle. Empty on FOSS boxes.
	OperatorAPI string
	// TrustedPubkeyHostSuffixes grade an SSH-key deep link fetched from a
	// matching host as "trusted" instead of "tls-verified".
	TrustedPubkeyHostSuffixes []string
	// LocalAuthURL overrides the Authelia portal link (default
	// https://local-auth-${DOMAIN}).
	LocalAuthURL string
}

func FromEnv() Config {
	return Config{
		Addr:                      def(os.Getenv("LISTEN_ADDR"), ":8080"),
		AssertionSecret:           os.Getenv("IDENTITY_ASSERTION_SECRET"),
		AssertionAudience:         def(os.Getenv("IDENTITY_ASSERTION_AUDIENCE"), "auth-console"),
		GateURL:                   strings.TrimRight(def(os.Getenv("APPSHIELD_GATE_URL"), "http://auth-console"), "/"),
		DevIdentity:               strings.TrimSpace(os.Getenv("DEV_IDENTITY")),
		Env:                       def(os.Getenv("AUTH_CONSOLE_ENV"), "production"),
		HostRoot:                  strings.TrimRight(strings.TrimSpace(os.Getenv("HOST_ROOT")), "/"),
		HostScripts:               strings.TrimRight(strings.TrimSpace(os.Getenv("HOST_SCRIPTS")), "/"),
		HostRootMount:             def(os.Getenv("HOST_ROOT_MOUNT"), "/host-root"),
		SelfContainer:             def(os.Getenv("SELF_CONTAINER"), "auth-console-app"),
		RunnerImage:               strings.TrimSpace(os.Getenv("RUNNER_IMAGE")),
		OperatorAPI:               strings.TrimRight(strings.TrimSpace(os.Getenv("OPERATOR_API")), "/"),
		TrustedPubkeyHostSuffixes: csv(os.Getenv("TRUSTED_PUBKEY_HOST_SUFFIXES")),
		LocalAuthURL:              strings.TrimSpace(os.Getenv("LOCAL_AUTH_URL")),
	}
}

func csv(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func def(v, fallback string) string {
	if v = strings.TrimSpace(v); v == "" {
		return fallback
	}
	return v
}
