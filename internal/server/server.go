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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
	"github.com/SawaMEN/Firewall-UI/internal/audit"
	"github.com/SawaMEN/Firewall-UI/internal/firewall"
	"github.com/SawaMEN/Firewall-UI/internal/history"
	"github.com/SawaMEN/Firewall-UI/internal/rollback"
	"github.com/SawaMEN/Firewall-UI/internal/security"
	"github.com/SawaMEN/Firewall-UI/internal/service"
	"github.com/SawaMEN/Firewall-UI/internal/updater"
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
	ConfigPath    string
	RuntimeConfig appconfig.Config
	Restart       func()
	Updater       *updater.Manager
	PortMonitor   *service.PortMonitor
	Audit         *audit.Logger
	History       *history.Store
	Rollbacks     *rollback.Manager
	mu            sync.Mutex
	sessions      map[string]session
	attempts      map[string]attempt
}

func New(user, password string, port int, assets fs.FS) *Server {
	cfg := appconfig.Default()
	cfg.ListenPort = port
	return &Server{
		Username:      user,
		Password:      password,
		Port:          port,
		Assets:        assets,
		RuntimeConfig: cfg,
		Rollbacks:     rollback.NewManager(),
		sessions:      map[string]session{},
		attempts:      map[string]attempt{},
	}
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
	_ = json.NewEncoder(w).Encode(map[string]any{"success": err == nil, "msg": message, "obj": obj})
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
	s.mu.Lock()
	allowedCIDRs := append([]string(nil), s.RuntimeConfig.AllowedCIDRs...)
	s.mu.Unlock()
	if !security.IPAllowed(r.RemoteAddr, allowedCIDRs) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "same-origin")
	if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/panel/api/") {
		s.static(w, r)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}

	if r.Method == http.MethodPost && r.Header.Get("Origin") != "" {
		origin, err := url.Parse(r.Header.Get("Origin"))
		if err != nil || !strings.EqualFold(origin.Host, r.Host) {
			reply(w, http.StatusForbidden, nil, fmt.Errorf("invalid request origin"))
			return
		}
	}
	if r.Method == http.MethodPost && r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		reply(w, http.StatusForbidden, nil, fmt.Errorf("cross-site request"))
		return
	}

	if r.URL.Path == "/api/login" && r.Method == http.MethodPost {
		s.login(w, r)
		return
	}

	cookie, err := r.Cookie("firewall_ui_session")
	if err != nil {
		reply(w, http.StatusUnauthorized, nil, fmt.Errorf("authentication required"))
		return
	}
	s.mu.Lock()
	sess, ok := s.sessions[cookie.Value]
	s.mu.Unlock()
	if !ok || time.Now().After(sess.expires) {
		reply(w, http.StatusUnauthorized, nil, fmt.Errorf("session expired"))
		return
	}
	if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.csrf)) != 1 {
		reply(w, http.StatusForbidden, nil, fmt.Errorf("invalid CSRF token"))
		return
	}

	if r.URL.Path == "/api/session" && r.Method == http.MethodGet {
		s.mu.Lock()
		totpEnabled := s.RuntimeConfig.TOTPEnabled
		s.mu.Unlock()
		reply(w, http.StatusOK, map[string]any{"csrf": sess.csrf, "username": s.Username, "totpEnabled": totpEnabled}, nil)
		return
	}
	if r.URL.Path == "/api/logout" && r.Method == http.MethodPost {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     cookie.Name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   s.SecureCookies || r.TLS != nil,
		})
		reply(w, http.StatusOK, nil, nil)
		return
	}
	if r.URL.Path == "/api/ports" && r.Method == http.MethodGet {
		if s.PortMonitor != nil {
			reply(w, http.StatusOK, s.PortMonitor.Snapshot(), nil)
			return
		}
		ports, err := service.ReadPorts("/proc")
		reply(w, http.StatusOK, service.PortSnapshot{Ports: ports, UpdatedAt: time.Now().UTC()}, err)
		return
	}
	if s.handleExtendedAPI(w, r, sess) {
		return
	}
	if r.URL.Path == "/api/settings" {
		s.settings(w, r)
		return
	}
	if r.URL.Path == "/api/update/status" {
		s.updateStatus(w, r)
		return
	}
	if r.URL.Path == "/api/update/apply" {
		s.applyUpdate(w, r)
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
	if a.count >= 5 || len(s.attempts) > 4096 {
		retryAfter := int(time.Until(a.until).Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		s.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		reply(w, http.StatusTooManyRequests, nil, fmt.Errorf("too many login attempts"))
		return
	}
	if a.count == 0 {
		a.until = now.Add(15 * time.Minute)
	}
	a.count++
	s.attempts[ip] = a
	s.mu.Unlock()

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code,omitempty"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}

	got, want := sha256.Sum256([]byte(req.Password)), sha256.Sum256([]byte(s.Password))
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 || req.Username != s.Username {
		reply(w, http.StatusUnauthorized, nil, fmt.Errorf("invalid credentials"))
		return
	}
	s.mu.Lock()
	totpEnabled, totpSecret := s.RuntimeConfig.TOTPEnabled, s.RuntimeConfig.TOTPSecret
	s.mu.Unlock()
	if totpEnabled && !security.ValidateTOTP(totpSecret, req.Code, now) {
		reply(w, http.StatusUnauthorized, nil, fmt.Errorf("invalid two-factor code"))
		return
	}

	id, csrf := token(), token()
	s.mu.Lock()
	delete(s.attempts, ip)
	if len(s.sessions) >= 1024 {
		s.mu.Unlock()
		reply(w, http.StatusTooManyRequests, nil, fmt.Errorf("session limit reached"))
		return
	}
	s.sessions[id] = session{csrf: csrf, expires: now.Add(12 * time.Hour)}
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "firewall_ui_session",
		Value:    id,
		Path:     "/",
		MaxAge:   43200,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   s.SecureCookies || r.TLS != nil,
	})
	reply(w, http.StatusOK, map[string]string{"csrf": csrf}, nil)
}

type runtimeSettingsResponse struct {
	ListenHost       string   `json:"listenHost"`
	ListenPort       int      `json:"listenPort"`
	ExternalPort     int      `json:"externalPort"`
	SecureCookies    bool     `json:"secureCookies"`
	TLSCert          string   `json:"tlsCert"`
	TLSKey           string   `json:"tlsKey"`
	TLSEnabled       bool     `json:"tlsEnabled"`
	UpdateChannel    string   `json:"updateChannel"`
	AllowedCIDRs     []string `json:"allowedCidrs"`
	TOTPEnabled      bool     `json:"totpEnabled"`
	RollbackSeconds  int      `json:"rollbackSeconds"`
	PortScanInterval int      `json:"portScanInterval"`
	Restarting       bool     `json:"restarting,omitempty"`
}

func runtimeSettingsView(cfg appconfig.Config, restarting bool) runtimeSettingsResponse {
	return runtimeSettingsResponse{
		ListenHost:       cfg.ListenHost,
		ListenPort:       cfg.ListenPort,
		ExternalPort:     cfg.ExternalPort,
		SecureCookies:    cfg.SecureCookies,
		TLSCert:          cfg.TLSCert,
		TLSKey:           cfg.TLSKey,
		TLSEnabled:       cfg.TLSCert != "" && cfg.TLSKey != "",
		UpdateChannel:    cfg.UpdateChannel,
		AllowedCIDRs:     append([]string(nil), cfg.AllowedCIDRs...),
		TOTPEnabled:      cfg.TOTPEnabled,
		RollbackSeconds:  cfg.RollbackSeconds,
		PortScanInterval: cfg.PortScanInterval,
		Restarting:       restarting,
	}
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.mu.Lock()
		cfg := s.RuntimeConfig
		s.mu.Unlock()
		reply(w, http.StatusOK, runtimeSettingsView(cfg, false), nil)
		return
	}
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}

	var req struct {
		TLSCert          *string  `json:"tlsCert"`
		TLSKey           *string  `json:"tlsKey"`
		ListenHost       string   `json:"listenHost"`
		ListenPort       int      `json:"listenPort"`
		ExternalPort     int      `json:"externalPort"`
		SecureCookies    bool     `json:"secureCookies"`
		UpdateChannel    string   `json:"updateChannel"`
		AllowedCIDRs     []string `json:"allowedCidrs"`
		RollbackSeconds  int      `json:"rollbackSeconds"`
		PortScanInterval int      `json:"portScanInterval"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	if s.ConfigPath == "" {
		reply(w, http.StatusConflict, nil, fmt.Errorf("runtime configuration file is not configured"))
		return
	}

	s.mu.Lock()
	cfg := s.RuntimeConfig
	s.mu.Unlock()
	oldCfg := cfg
	if req.TLSCert != nil {
		cfg.TLSCert = strings.TrimSpace(*req.TLSCert)
	}
	if req.TLSKey != nil {
		cfg.TLSKey = strings.TrimSpace(*req.TLSKey)
	}
	cfg.ListenHost = strings.TrimSpace(req.ListenHost)
	cfg.ListenPort = req.ListenPort
	cfg.ExternalPort = req.ExternalPort
	cfg.SecureCookies = req.SecureCookies
	if strings.TrimSpace(req.UpdateChannel) != "" {
		cfg.UpdateChannel = strings.ToLower(strings.TrimSpace(req.UpdateChannel))
	}
	cfg.AllowedCIDRs = security.NormalizeCIDRs(req.AllowedCIDRs)
	if req.RollbackSeconds != 0 {
		cfg.RollbackSeconds = req.RollbackSeconds
	}
	if req.PortScanInterval != 0 {
		cfg.PortScanInterval = req.PortScanInterval
	}
	if err := appconfig.Validate(cfg); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}

	if len(cfg.AllowedCIDRs) > 0 && !security.IPAllowed(r.RemoteAddr, cfg.AllowedCIDRs) {
		reply(w, http.StatusBadRequest, nil, fmt.Errorf("allowed CIDRs would lock out the current client"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if cfg.ListenPort != s.Port {
		if err := s.Firewall.RememberSafetyPort(cfg.ListenPort); err != nil {
			reply(w, http.StatusOK, nil, err)
			return
		}
		status, statusErr := s.Firewall.GetManagedStatusSafe(ctx, s.Port)
		if statusErr == nil && status.Supported && status.Enabled {
			if _, err := s.Firewall.SyncManagedSafe(ctx, cfg.ListenPort); err != nil {
				reply(w, http.StatusOK, nil, fmt.Errorf("protect new panel port: %w", err))
				return
			}
		}
	}

	if err := appconfig.Save(s.ConfigPath, cfg); err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}

	s.mu.Lock()
	s.RuntimeConfig = cfg
	s.mu.Unlock()
	channelChanged := oldCfg.UpdateChannel != cfg.UpdateChannel
	requiresRestart := oldCfg.TLSCert != cfg.TLSCert || oldCfg.TLSKey != cfg.TLSKey || oldCfg.ListenHost != cfg.ListenHost || oldCfg.ListenPort != cfg.ListenPort || oldCfg.ExternalPort != cfg.ExternalPort || oldCfg.SecureCookies != cfg.SecureCookies || oldCfg.PortScanInterval != cfg.PortScanInterval
	restarting := requiresRestart && s.Restart != nil
	if channelChanged && !restarting && s.Updater != nil {
		s.Updater.Trigger()
	}
	reply(w, http.StatusOK, runtimeSettingsView(cfg, restarting), nil)

	if restarting {
		go func() {
			time.Sleep(350 * time.Millisecond)
			s.Restart()
		}()
	}
}

func (s *Server) updateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	if s.Updater == nil {
		reply(w, http.StatusServiceUnavailable, nil, fmt.Errorf("updater is not configured"))
		return
	}
	s.mu.Lock()
	channel := s.RuntimeConfig.UpdateChannel
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	status, err := s.Updater.Check(ctx, channel)
	reply(w, http.StatusOK, status, err)
}

func (s *Server) applyUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	if s.Updater == nil {
		reply(w, http.StatusServiceUnavailable, nil, fmt.Errorf("updater is not configured"))
		return
	}
	s.mu.Lock()
	channel := s.RuntimeConfig.UpdateChannel
	s.mu.Unlock()
	if channel != "stable" {
		reply(w, http.StatusConflict, nil, fmt.Errorf("dev updates are installed automatically"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	status, err := s.Updater.Apply(ctx, "stable")
	reply(w, http.StatusOK, status, err)
}

func (s *Server) manage(w http.ResponseWriter, r *http.Request) {
	operation := strings.TrimPrefix(r.URL.Path, "/panel/api/server/firewall/")
	if operation == r.URL.Path {
		reply(w, http.StatusNotFound, nil, fmt.Errorf("not found"))
		return
	}
	if operation == "status" && r.Method != http.MethodGet || operation != "status" && r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	if operation != "status" &&
		operation != "enabled" &&
		operation != "auto-sync" &&
		operation != "ping" &&
		operation != "sync" &&
		operation != "install-ufw" &&
		operation != "rules/add" &&
		operation != "rules/delete" {
		reply(w, http.StatusNotFound, nil, fmt.Errorf("not found"))
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
			reply(w, http.StatusBadRequest, nil, err)
			return
		}
		if (operation == "enabled" || operation == "auto-sync" || operation == "ping") && req.Enabled == nil {
			reply(w, http.StatusBadRequest, nil, fmt.Errorf("enabled is required"))
			return
		}
	}

	var before *service.FirewallBackup
	if operation != "status" && operation != "install-ufw" {
		snapshot, snapshotErr := s.Firewall.ExportBackup()
		if snapshotErr != nil {
			reply(w, http.StatusOK, nil, snapshotErr)
			return
		}
		before = &snapshot
		if err := s.Firewall.MigrateManagedBackendIfNeeded(ctx); err != nil {
			reply(w, http.StatusOK, nil, err)
			return
		}
		if err := s.Firewall.RememberSafetyPort(s.Port); err != nil {
			reply(w, http.StatusOK, nil, err)
			return
		}
		if err := s.Firewall.MarkControlInitialized(); err != nil {
			reply(w, http.StatusOK, nil, err)
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
		reply(w, http.StatusOK, nil, err)
		return
	}

	ping, err := s.Firewall.ManagedPingEnabled()
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	var pending *rollback.Pending
	if before != nil {
		tx, txErr := s.beginRollback(*before, "firewall."+operation, r)
		if txErr != nil {
			reply(w, http.StatusOK, nil, txErr)
			return
		}
		pending = &tx
		s.audit(r, "firewall."+operation, true, "", map[string]any{
			"port": req.Port, "protocol": req.Protocol, "enabled": req.Enabled,
		})
	}
	detected := firewall.Detect(ctx)
	reply(w, http.StatusOK, struct {
		service.FirewallManagedStatus
		Ping       bool              `json:"pingEnabled"`
		CanInstall bool              `json:"canInstallUfw"`
		Rollback   *rollback.Pending `json:"rollback,omitempty"`
	}{
		FirewallManagedStatus: status,
		Ping:                  ping,
		CanInstall:            !detected.Installed && os.Geteuid() == 0,
		Rollback:              pending,
	}, nil)
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
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
		http.Error(w, "Build frontend first: cd frontend && npm ci && npm run build", http.StatusServiceUnavailable)
		return
	}
	copy := r.Clone(r.Context())
	copy.URL.Path = "/" + name
	if name == "index.html" {
		copy.URL.Path = "/"
	}
	http.FileServer(http.FS(s.Assets)).ServeHTTP(w, copy)
}
