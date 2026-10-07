package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/firewall"
	"github.com/SawaMEN/Firewall-UI/internal/service"
)

type session struct {
	csrf    string
	expires time.Time
}
type attempt struct {
	count int
	until time.Time
}
type Server struct {
	SecureCookies bool
	Firewall      service.FirewallService
	Password      string
	Username      string
	Port          int
	Assets        fs.FS
	mu            sync.Mutex
	sessions      map[string]session
	attempts      map[string]attempt
}

func New(user, password string, port int, assets fs.FS) *Server {
	return &Server{Username: user, Password: password, Port: port, Assets: assets, sessions: map[string]session{}, attempts: map[string]attempt{}}
}
func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func reply(w http.ResponseWriter, status int, obj any, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	message := ""
	if err != nil {
		message = err.Error()
	}
	json.NewEncoder(w).Encode(map[string]any{"success": err == nil, "msg": message, "obj": obj})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request must contain one JSON object")
	}
	return nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/panel/api/") {
		s.static(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		reply(w, 405, nil, fmt.Errorf("method not allowed"))
		return
	}
	// Reject browser cross-site login/logout and mutations; proxy headers are never trusted.
	if r.Method == http.MethodPost && r.Header.Get("Origin") != "" {
		origin, err := url.Parse(r.Header.Get("Origin"))
		if err != nil || !strings.EqualFold(origin.Host, r.Host) {
			reply(w, 403, nil, fmt.Errorf("invalid request origin"))
			return
		}
	}
	if r.Method == http.MethodPost && r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		reply(w, 403, nil, fmt.Errorf("cross-site request"))
		return
	}
	if r.URL.Path == "/api/login" && r.Method == http.MethodPost {
		s.login(w, r)
		return
	}
	cookie, err := r.Cookie("firewall_ui_session")
	if err != nil {
		reply(w, 401, nil, fmt.Errorf("authentication required"))
		return
	}
	s.mu.Lock()
	sess, ok := s.sessions[cookie.Value]
	s.mu.Unlock()
	if !ok || time.Now().After(sess.expires) {
		reply(w, 401, nil, fmt.Errorf("session expired"))
		return
	}
	if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.csrf)) != 1 {
		reply(w, 403, nil, fmt.Errorf("invalid CSRF token"))
		return
	}
	if r.URL.Path == "/api/session" && r.Method == http.MethodGet {
		reply(w, 200, map[string]string{"csrf": sess.csrf, "username": s.Username}, nil)
		return
	}
	if r.URL.Path == "/api/logout" && r.Method == http.MethodPost {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: cookie.Name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.SecureCookies || r.TLS != nil})
		reply(w, 200, nil, nil)
		return
	}
	if r.URL.Path == "/api/ports" && r.Method == http.MethodGet {
		ports, err := service.ReadPorts("/proc")
		reply(w, 200, ports, err)
		return
	}
	s.manage(w, r)
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	s.mu.Lock()
	for k, v := range s.attempts {
		if now.After(v.until) {
			delete(s.attempts, k)
		}
	}
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	a := s.attempts[ip]
	if a.count >= 10 || len(s.attempts) > 4096 {
		s.mu.Unlock()
		reply(w, 429, nil, fmt.Errorf("too many login attempts"))
		return
	}
	if a.count == 0 {
		a.until = now.Add(10 * time.Minute)
	}
	a.count++
	s.attempts[ip] = a
	s.mu.Unlock()
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, 400, nil, err)
		return
	}
	got, want := sha256.Sum256([]byte(req.Password)), sha256.Sum256([]byte(s.Password))
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 || req.Username != s.Username {
		reply(w, 401, nil, fmt.Errorf("invalid credentials"))
		return
	}
	id, csrf := token(), token()
	s.mu.Lock()
	delete(s.attempts, ip)
	if len(s.sessions) >= 1024 {
		s.mu.Unlock()
		reply(w, 429, nil, fmt.Errorf("session limit reached"))
		return
	}
	s.sessions[id] = session{csrf, now.Add(12 * time.Hour)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "firewall_ui_session", Value: id, Path: "/", MaxAge: 43200, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.SecureCookies || r.TLS != nil})
	reply(w, 200, map[string]string{"csrf": csrf}, nil)
}
func (s *Server) manage(w http.ResponseWriter, r *http.Request) {
	operation := strings.TrimPrefix(r.URL.Path, "/panel/api/server/firewall/")
	if operation == r.URL.Path {
		reply(w, 404, nil, fmt.Errorf("not found"))
		return
	}
	if operation == "status" && r.Method != http.MethodGet || operation != "status" && r.Method != http.MethodPost {
		reply(w, 405, nil, fmt.Errorf("method not allowed"))
		return
	}
	if operation != "status" && operation != "enabled" && operation != "auto-sync" && operation != "ping" && operation != "sync" && operation != "install-ufw" && operation != "rules/add" && operation != "rules/delete" {
		reply(w, 404, nil, fmt.Errorf("not found"))
		return
	}
	timeout := 30 * time.Second
	if operation == "install-ufw" {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	var req struct {
		Enabled  *bool  `json:"enabled"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Label    string `json:"label"`
	}
	if operation == "enabled" || operation == "auto-sync" || operation == "ping" || strings.HasPrefix(operation, "rules/") {
		if err := decode(w, r, &req); err != nil {
			reply(w, 400, nil, err)
			return
		}
		if (operation == "enabled" || operation == "auto-sync" || operation == "ping") && req.Enabled == nil {
			reply(w, 400, nil, fmt.Errorf("enabled is required"))
			return
		}
	}
	if operation != "status" && operation != "install-ufw" {
		if err := s.Firewall.MigrateManagedBackendIfNeeded(ctx); err != nil {
			reply(w, 200, nil, err)
			return
		}
		if err := s.Firewall.RememberSafetyPort(s.Port); err != nil {
			reply(w, 200, nil, err)
			return
		}
		if err := s.Firewall.MarkControlInitialized(); err != nil {
			reply(w, 200, nil, err)
			return
		}
	}
	var status service.FirewallManagedStatus
	var err error
	switch operation {
	case "status":
		status, err = s.Firewall.GetManagedStatusSafe(ctx, s.Port)
	case "enabled":
		status, err = s.Firewall.SetManagedEnabledSafe(ctx, *req.Enabled, s.Port)
		if err == nil {
			status, err = s.Firewall.ReconcileManagedPingState(ctx, s.Port)
		}
	case "auto-sync":
		status, err = s.Firewall.SetManagedAutoSyncPreferenceSafe(ctx, *req.Enabled, s.Port)
	case "ping":
		status, err = s.Firewall.SetManagedPingEnabledSafe(ctx, *req.Enabled, s.Port)
	case "sync":
		status, err = s.Firewall.SyncManagedSafe(ctx, s.Port)
	case "rules/add":
		status, err = s.Firewall.AddManagedManualRuleSafe(ctx, req.Port, req.Protocol, req.Label, s.Port)
	case "rules/delete":
		status, err = s.Firewall.DeleteManagedManualRuleSafe(ctx, req.Port, req.Protocol, s.Port)
	case "install-ufw":
		detected := firewall.Detect(ctx)
		if !detected.Installed {
			_, err = firewall.InstallUFW(ctx)
		}
		if err == nil {
			status, err = s.Firewall.GetManagedStatusSafe(ctx, s.Port)
		}
	}
	if err != nil {
		reply(w, 200, nil, err)
		return
	}
	ping, err := s.Firewall.ManagedPingEnabled()
	detected := firewall.Detect(ctx)
	reply(w, 200, struct {
		service.FirewallManagedStatus
		Ping       bool `json:"pingEnabled"`
		CanInstall bool `json:"canInstallUfw"`
	}{status, ping, !detected.Installed && os.Geteuid() == 0}, err)
}
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(405)
		return
	}
	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" || name == "." {
		name = "index.html"
	}
	if _, err := fs.Stat(s.Assets, name); err != nil {
		if strings.HasPrefix(name, "assets/") {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
	}
	if _, err := fs.Stat(s.Assets, name); err != nil {
		http.Error(w, "Build frontend first: cd frontend && npm ci && npm run build", 503)
		return
	}
	copy := r.Clone(r.Context())
	copy.URL.Path = "/" + name
	http.FileServer(http.FS(s.Assets)).ServeHTTP(w, copy)
}
