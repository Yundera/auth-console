package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yundera/auth-console/internal/access"
	"github.com/yundera/auth-console/internal/auth"
	"github.com/yundera/auth-console/internal/gatectl"
	"github.com/yundera/auth-console/internal/hostverb"
	"github.com/yundera/auth-console/internal/pubkey"
)

// ---- me ----------------------------------------------------------------------

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	local := s.cfg.LocalAuthURL
	if local == "" {
		if d := s.env().Get("DOMAIN"); d != "" {
			local = "https://local-auth-" + d
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"identity":     id,
		"isAdmin":      id.IsAdmin(),
		"localAuthUrl": local,
		"logoutUrl":    "/nhl-auth/logout",
		"version":      Version,
	})
}

func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.caps())
}

// handleOnboarding is readable by every user: the status says whether the box
// has an owner, nothing more. Reset is terminal-only by decision.
func (s *Server) handleOnboarding(w http.ResponseWriter, r *http.Request) {
	if !s.caps().Onboarding {
		writeError(w, http.StatusNotFound, "onboarding is not available on this box")
		return
	}
	v, err := s.scripts().OnboardingStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var out struct {
		Claimed   bool   `json:"claimed"`
		Completed bool   `json:"completed"`
		Username  string `json:"username"`
	}
	if err := s.runJSON(r.Context(), v, &out); err != nil {
		verbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- local (Authelia) accounts -----------------------------------------------

type user struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayname"`
	Email       string   `json:"email"`
	Groups      []string `json:"groups"`
	Disabled    bool     `json:"disabled"`
	// Protected is the owner account (LOCAL_ADMIN_USER): the script refuses to
	// delete it or change its email. Older scripts don't report it, hence the
	// pointer — see listUsers.
	Protected *bool `json:"protected,omitempty"`
}

func (s *Server) listUsers(ctx context.Context) ([]user, error) {
	v, err := s.scripts().UsersList()
	if err != nil {
		return nil, err
	}
	users := []user{}
	if err := s.runJSON(ctx, v, &users); err != nil {
		return nil, err
	}
	// A template older than the `protected` field: derive it the way the
	// script does (LOCAL_ADMIN_USER, else `admin`) instead of settings-center-
	// app's hard-coded 'admin', which was wrong once the owner chose a name.
	owner := s.env().Get("LOCAL_ADMIN_USER")
	if owner == "" {
		owner = "admin"
	}
	for i := range users {
		if users[i].Protected == nil {
			p := users[i].Username == owner
			users[i].Protected = &p
		}
		if users[i].Groups == nil {
			users[i].Groups = []string{}
		}
	}
	return users, nil
}

func (s *Server) handleUsersList(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	users, err := s.listUsers(r.Context())
	if err != nil {
		verbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"users":       users,
		"currentUser": id.User,
		"collectedAt": time.Now().UTC().Format(time.RFC3339),
	})
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleUsersAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username    string `json:"username"`
		DisplayName string `json:"displayname"`
		Email       string `json:"email"`
		IsAdmin     bool   `json:"isAdmin"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	v, err := s.scripts().UsersAdd(strings.TrimSpace(in.Username), in.DisplayName, strings.TrimSpace(in.Email), in.IsAdmin)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var out credentials
	if err := s.runJSON(r.Context(), v, &out); err != nil {
		verbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUsersDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	username := chi.URLParam(r, "username")
	if username == id.User {
		writeError(w, http.StatusBadRequest, "You cannot delete the account you are signed in as")
		return
	}
	v, err := s.scripts().UsersDelete(username)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var out map[string]any
	if err := s.runJSON(r.Context(), v, &out); err != nil {
		verbError(w, err)
		return
	}
	resp := map[string]any{"status": "success", "username": username}
	if _, ok := s.gate.Revoke(r.Context(), gatectl.Selector{User: username}); !ok {
		resp["warning"] = "Account deleted, but its open sessions on this console could not be ended."
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUsersResetPassword(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	username := chi.URLParam(r, "username")
	v, err := s.scripts().UsersSetPassword(username)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var out credentials
	if err := s.runJSON(r.Context(), v, &out); err != nil {
		verbError(w, err)
		return
	}
	// End every session opened with the old password — except the one this
	// request came from, when an admin resets their own.
	sel := gatectl.Selector{User: username}
	if username == id.User {
		if c, err := r.Cookie("appshield_session"); err == nil && c.Value != "" {
			sel.Except = []string{c.Value}
		}
	}
	s.gate.Revoke(r.Context(), sel)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUsersSetEmail(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")
	var in struct {
		Email string `json:"email"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	v, err := s.scripts().UsersSetEmail(username, strings.TrimSpace(in.Email))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var out map[string]any
	if err := s.runJSON(r.Context(), v, &out); err != nil {
		verbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "username": username, "email": strings.TrimSpace(in.Email)})
}

// ---- host SSH access ---------------------------------------------------------

func (s *Server) collectAccess(ctx context.Context) (access.Report, error) {
	res, err := s.runVerb(ctx, hostverb.AccessInfo())
	if err != nil {
		return access.Report{}, err
	}
	if res.ExitCode != 0 {
		return access.Report{}, scriptError(res)
	}
	fp := ""
	if k, err := s.supportKeyInfo(ctx); err == nil {
		fp = k.Fingerprint
	}
	return access.Parse(res.Stdout, fp), nil
}

func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	rep, err := s.collectAccess(r.Context())
	if err != nil {
		verbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accounts":         rep.Accounts,
		"recentLogins":     rep.RecentLogins,
		"dashboardAccount": s.caps().DashboardAccount,
		"collectedAt":      time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleAccessAddKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username  string `json:"username"`
		PublicKey string `json:"publicKey"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	v, err := hostverb.AccessAddKey(in.Username, in.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.runVerb(r.Context(), v)
	if err != nil {
		verbError(w, err)
		return
	}
	switch res.ExitCode {
	case 0:
	case hostverb.ExitUserNotFound:
		writeError(w, http.StatusNotFound, fmt.Sprintf("User '%s' does not exist", in.Username))
		return
	case hostverb.ExitHomeMissing:
		writeError(w, http.StatusConflict, fmt.Sprintf("Home directory for '%s' does not exist", in.Username))
		return
	case hostverb.ExitUnsafePath:
		writeError(w, http.StatusConflict, fmt.Sprintf("'%s' has a symlinked ~/.ssh or authorized_keys; refusing to write through it", in.Username))
		return
	default:
		writeError(w, http.StatusBadGateway, scriptError(res).Error())
		return
	}
	status := "unknown"
	switch {
	case strings.Contains(res.Stdout, "ALREADY_PRESENT"):
		status = "already-present"
	case strings.Contains(res.Stdout, "ADDED"):
		status = "added"
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}

var removedRe = regexp.MustCompile(`REMOVED:(\d+)`)

func (s *Server) handleAccessRemoveKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username    string `json:"username"`
		Fingerprint string `json:"fingerprint"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	v, err := hostverb.AccessRemoveKey(in.Username, in.Fingerprint)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The Yundera admin app reaches the host with its local-admin-access key on
	// the dashboard account: removing it breaks that app. The UI disables the
	// button; this is the enforcement, so it looks the key up on the host.
	if dash := s.caps().DashboardAccount; dash != "" && in.Username == dash {
		rep, err := s.collectAccess(r.Context())
		if err != nil {
			verbError(w, err)
			return
		}
		for _, a := range rep.Accounts {
			if a.Username != dash {
				continue
			}
			for _, k := range a.AuthorizedKeys {
				if k.Fingerprint == in.Fingerprint && k.IsAdminKey {
					writeError(w, http.StatusConflict, "This is the admin app's own key — it is managed automatically")
					return
				}
			}
		}
	}
	res, err := s.runVerb(r.Context(), v)
	if err != nil {
		verbError(w, err)
		return
	}
	switch res.ExitCode {
	case 0:
	case hostverb.ExitUserNotFound:
		writeError(w, http.StatusNotFound, fmt.Sprintf("User '%s' does not exist", in.Username))
		return
	case hostverb.ExitUnsafePath:
		writeError(w, http.StatusConflict, fmt.Sprintf("'%s' has a symlinked ~/.ssh or authorized_keys; refusing to write through it", in.Username))
		return
	default:
		writeError(w, http.StatusBadGateway, scriptError(res).Error())
		return
	}
	if m := removedRe.FindStringSubmatch(res.Stdout); m != nil {
		n, _ := strconv.Atoi(m[1])
		writeJSON(w, http.StatusOK, map[string]any{"status": "removed", "removed": n})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "not-found", "removed": 0})
}

func (s *Server) handleFetchPubkey(w http.ResponseWriter, r *http.Request) {
	res, err := s.pubkey.Fetch(r.Context(), r.URL.Query().Get("url"))
	if err != nil {
		var br pubkey.BadRequest
		if errors.As(err, &br) {
			writeError(w, http.StatusBadRequest, br.Msg)
		} else {
			writeError(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ---- support access (Yundera only) -------------------------------------------

type supportKey struct {
	Algorithm   string `json:"algorithm"`
	Comment     string `json:"comment"`
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
}

type supportKeyCache struct {
	at  time.Time
	key supportKey
}

// supportKeyInfo is the operator's support key (GET ${OPERATOR_API}/support/
// ssh-key), cached 5 minutes like settings-center-app's SupportKey.ts.
func (s *Server) supportKeyInfo(ctx context.Context) (supportKey, error) {
	if s.cfg.OperatorAPI == "" {
		return supportKey{}, errors.New("OPERATOR_API not configured")
	}
	s.supportMu.Lock()
	c := s.supportKey
	s.supportMu.Unlock()
	if c != nil && time.Since(c.at) < 5*time.Minute {
		return c.key, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.OperatorAPI+"/support/ssh-key", nil)
	if err != nil {
		return supportKey{}, err
	}
	res, err := s.http.Do(req)
	if err != nil {
		return supportKey{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return supportKey{}, fmt.Errorf("operator /support/ssh-key returned %d", res.StatusCode)
	}
	var k supportKey
	if err := json.NewDecoder(res.Body).Decode(&k); err != nil || k.PublicKey == "" || k.Fingerprint == "" {
		return supportKey{}, errors.New("operator returned a malformed support key")
	}
	if k.Comment == "" {
		k.Comment = "pcs-support"
	}
	s.supportMu.Lock()
	s.supportKey = &supportKeyCache{at: time.Now(), key: k}
	s.supportMu.Unlock()
	return k, nil
}

func (s *Server) supportStatus(ctx context.Context) (map[string]any, error) {
	k, err := s.supportKeyInfo(ctx)
	if err != nil {
		return nil, err
	}
	v, err := s.scripts().SupportStatus(s.cfg.HostRoot)
	if err != nil {
		return nil, err
	}
	res, err := s.runVerb(ctx, v)
	if err != nil {
		return nil, err
	}
	raw, present := "", false
	for _, line := range strings.Split(res.Stdout, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ENSURE="):
			raw = strings.TrimPrefix(line, "ENSURE=")
		case strings.HasPrefix(line, "FP="):
			if strings.TrimPrefix(line, "FP=") == k.Fingerprint {
				present = true
			}
		}
	}
	lower := strings.ToLower(raw)
	optedOut := lower == "false" || lower == "0" || lower == "no" || lower == "off"
	return map[string]any{
		"ensure":        !optedOut,
		"rawValue":      raw,
		"accessEnabled": present,
		"username":      "admin",
		"fingerprint":   k.Fingerprint,
		"comment":       k.Comment,
	}, nil
}

func (s *Server) handleSupportGet(w http.ResponseWriter, r *http.Request) {
	if !s.caps().Support {
		writeError(w, http.StatusNotFound, "support access is not available on this box")
		return
	}
	st, err := s.supportStatus(r.Context())
	if err != nil {
		verbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleSupportPut(w http.ResponseWriter, r *http.Request) {
	if !s.caps().Support {
		writeError(w, http.StatusNotFound, "support access is not available on this box")
		return
	}
	var in struct {
		Ensure *bool `json:"ensure"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if in.Ensure == nil {
		writeError(w, http.StatusBadRequest, "Body must include { ensure: boolean }")
		return
	}
	v, err := s.scripts().SupportSet(*in.Ensure)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var out struct {
		Enabled *bool `json:"enabled"`
	}
	if err := s.runJSON(r.Context(), v, &out); err != nil {
		verbError(w, err)
		return
	}
	if out.Enabled == nil {
		writeError(w, http.StatusBadGateway, `feature-support-key.sh returned no "enabled" field`)
		return
	}
	st, err := s.supportStatus(r.Context())
	if err != nil {
		verbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}
