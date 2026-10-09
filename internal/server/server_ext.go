package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
	"github.com/SawaMEN/Firewall-UI/internal/audit"
	"github.com/SawaMEN/Firewall-UI/internal/history"
	"github.com/SawaMEN/Firewall-UI/internal/rollback"
	"github.com/SawaMEN/Firewall-UI/internal/security"
	"github.com/SawaMEN/Firewall-UI/internal/service"
)

type fullBackup struct {
	Version   int                    `json:"version"`
	CreatedAt time.Time              `json:"createdAt"`
	Firewall  service.FirewallBackup `json:"firewall"`
	Runtime   runtimeBackup          `json:"runtime"`
}

type runtimeBackup struct {
	PublicHost       string   `json:"publicHost,omitempty"`
	ListenHost       string   `json:"listenHost"`
	ListenPort       int      `json:"listenPort"`
	ExternalPort     int      `json:"externalPort"`
	SecureCookies    bool     `json:"secureCookies"`
	TLSCert          string   `json:"tlsCert,omitempty"`
	TLSKey           string   `json:"tlsKey,omitempty"`
	UpdateChannel    string   `json:"updateChannel"`
	AllowedCIDRs     []string `json:"allowedCidrs,omitempty"`
	RollbackSeconds  int      `json:"rollbackSeconds"`
	PortScanInterval int      `json:"portScanInterval"`
}

type dashboardResponse struct {
	Backend         string                  `json:"backend"`
	FirewallEnabled bool                    `json:"firewallEnabled"`
	AutoSync        bool                    `json:"autoSync"`
	ListeningPorts  int                     `json:"listeningPorts"`
	PublicPorts     int                     `json:"publicPorts"`
	ManagedRules    int                     `json:"managedRules"`
	ManualRules     int                     `json:"manualRules"`
	AdvancedRules   int                     `json:"advancedRules"`
	Containers      int                     `json:"containers"`
	RiskyPorts      []service.Port          `json:"riskyPorts"`
	ContainerPorts  []service.ContainerPort `json:"containerPorts"`
	LastPortScan    time.Time               `json:"lastPortScan"`
}

func (s *Server) handleExtendedAPI(w http.ResponseWriter, r *http.Request, sess session) bool {
	switch r.URL.Path {
	case "/api/ports/stream":
		s.streamPorts(w, r)
	case "/api/security/credentials":
		s.credentials(w, r)
	case "/api/firewall/port":
		s.setPortAccess(w, r)
	case "/api/dashboard":
		s.dashboard(w, r)
	case "/api/security/totp/setup":
		s.setupTOTP(w, r)
	case "/api/security/totp/confirm":
		s.confirmTOTP(w, r)
	case "/api/security/totp/disable":
		s.disableTOTP(w, r)
	case "/api/audit":
		s.auditLog(w, r)
	case "/api/history":
		s.historyList(w, r)
	case "/api/history/restore":
		s.historyRestore(w, r)
	case "/api/backup":
		s.backup(w, r)
	case "/api/backup/restore":
		s.restoreBackup(w, r)
	case "/api/firewall/advanced":
		s.advancedRules(w, r)
	case "/api/firewall/advanced/delete":
		s.deleteAdvancedRule(w, r)
	case "/api/firewall/rollback/confirm":
		s.confirmRollback(w, r)
	case "/api/system/restart":
		s.restartService(w, r)
	default:
		return false
	}
	_ = sess
	return true
}

func (s *Server) streamPorts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	if s.PortMonitor == nil {
		reply(w, http.StatusServiceUnavailable, nil, fmt.Errorf("port monitor is not configured"))
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		reply(w, http.StatusInternalServerError, nil, fmt.Errorf("streaming is unavailable"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch, cancel := s.PortMonitor.Subscribe()
	defer cancel()
	cookie, _ := r.Cookie("firewall_ui_session")
	validSession := func() bool {
		if cookie == nil {
			return false
		}
		s.mu.Lock()
		session, ok := s.sessions[cookie.Value]
		s.mu.Unlock()
		return ok && time.Now().Before(session.expires)
	}
	keepAlive := time.NewTicker(20 * time.Second)
	defer keepAlive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case snapshot, ok := <-ch:
			if !ok {
				return
			}
			if !validSession() {
				return
			}
			raw, _ := json.Marshal(snapshot)
			_, _ = fmt.Fprintf(w, "event: ports\ndata: %s\n\n", raw)
			flusher.Flush()
		case <-keepAlive.C:
			if !validSession() {
				return
			}
			_, _ = fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	status, err := s.Firewall.GetManagedStatusSafe(ctx, s.Port)
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	advanced, err := s.Firewall.AdvancedRules()
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	snapshot := service.PortSnapshot{}
	if s.PortMonitor != nil {
		snapshot = s.PortMonitor.Snapshot()
	} else {
		snapshot.Ports, err = service.ReadPorts("/proc")
		snapshot.UpdatedAt = time.Now().UTC()
		if err != nil {
			reply(w, http.StatusOK, nil, err)
			return
		}
	}

	covered := map[string]bool{}
	if status.Enabled {
		for _, rule := range status.Rules {
			if !rule.Exists {
				continue
			}
			if rule.Port > 0 {
				covered[fmt.Sprintf("%d/%s", rule.Port, rule.Protocol)] = true
			}
		}
		for _, rule := range advanced {
			if rule.Action != "allow" || rule.PortStart == 0 {
				continue
			}
			for port := rule.PortStart; port <= rule.PortEnd && port-rule.PortStart < 2048; port++ {
				covered[fmt.Sprintf("%d/%s", port, rule.Protocol)] = true
			}
		}
	}

	listening, public, risky := summarizePorts(snapshot.Ports, covered)
	reply(w, http.StatusOK, dashboardResponse{
		Backend:         status.Backend,
		FirewallEnabled: status.Enabled,
		AutoSync:        status.AutoSync,
		ListeningPorts:  listening,
		PublicPorts:     public,
		ManagedRules:    len(status.Rules),
		ManualRules:     len(status.ManualRules),
		AdvancedRules:   len(advanced),
		Containers:      uniqueContainers(snapshot.Containers),
		RiskyPorts:      risky,
		ContainerPorts:  snapshot.Containers,
		LastPortScan:    snapshot.UpdatedAt,
	}, nil)
}

func summarizePorts(ports []service.Port, covered map[string]bool) (int, int, []service.Port) {
	risky := []service.Port{}
	listening, public := 0, 0
	for _, port := range ports {
		if !port.Listening {
			continue
		}
		listening++
		isPublic := port.Address == "0.0.0.0" || port.Address == "::"
		if isPublic {
			public++
		}
		if isPublic && len(risky) < 30 && !covered[fmt.Sprintf("%d/%s", port.Port, port.Protocol)] {
			risky = append(risky, port)
		}
	}
	return listening, public, risky
}

func runtimeRestartRequired(old, next appconfig.Config) bool {
	return old.TLSCert != next.TLSCert || old.TLSKey != next.TLSKey || old.ListenHost != next.ListenHost || old.ListenPort != next.ListenPort || old.ExternalPort != next.ExternalPort || old.SecureCookies != next.SecureCookies || old.PortScanInterval != next.PortScanInterval
}

func uniqueContainers(ports []service.ContainerPort) int {
	seen := map[string]bool{}
	for _, item := range ports {
		seen[item.Runtime+":"+item.ContainerID] = true
	}
	return len(seen)
}

func (s *Server) setupTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		reply(w, http.StatusInternalServerError, nil, err)
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()

	s.mu.Lock()
	cfg := s.RuntimeConfig
	if cfg.TOTPEnabled {
		s.mu.Unlock()
		reply(w, http.StatusConflict, nil, fmt.Errorf("two-factor authentication is already enabled"))
		return
	}
	cfg.TOTPSecret = secret
	s.mu.Unlock()
	if err := appconfig.Save(s.ConfigPath, cfg); err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.mu.Lock()
	s.RuntimeConfig = cfg
	s.mu.Unlock()
	s.audit(r, "totp.setup", true, "", nil)
	reply(w, http.StatusOK, map[string]string{
		"secret": secret,
		"uri":    security.ProvisioningURI(secret, s.username(), "Firewall-UI"),
	}, nil)
}

func (s *Server) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()

	s.mu.Lock()
	cfg := s.RuntimeConfig
	s.mu.Unlock()
	if cfg.TOTPSecret == "" || !security.ValidateTOTP(cfg.TOTPSecret, req.Code, time.Now()) {
		reply(w, http.StatusBadRequest, nil, fmt.Errorf("invalid two-factor code"))
		return
	}
	cfg.TOTPEnabled = true
	if err := appconfig.Save(s.ConfigPath, cfg); err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.mu.Lock()
	s.RuntimeConfig = cfg
	s.mu.Unlock()
	s.audit(r, "totp.enable", true, "", nil)
	reply(w, http.StatusOK, map[string]bool{"enabled": true}, nil)
}

func (s *Server) disableTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()

	s.mu.Lock()
	cfg := s.RuntimeConfig
	s.mu.Unlock()
	if !cfg.TOTPEnabled {
		reply(w, http.StatusOK, map[string]bool{"enabled": false}, nil)
		return
	}
	if !security.ValidateTOTP(cfg.TOTPSecret, req.Code, time.Now()) {
		reply(w, http.StatusBadRequest, nil, fmt.Errorf("invalid two-factor code"))
		return
	}
	cfg.TOTPEnabled = false
	cfg.TOTPSecret = ""
	if err := appconfig.Save(s.ConfigPath, cfg); err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.mu.Lock()
	s.RuntimeConfig = cfg
	s.mu.Unlock()
	s.audit(r, "totp.disable", true, "", nil)
	reply(w, http.StatusOK, map[string]bool{"enabled": false}, nil)
}

func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	if s.Audit == nil {
		reply(w, http.StatusOK, []audit.Entry{}, nil)
		return
	}
	entries, err := s.Audit.Recent(300)
	reply(w, http.StatusOK, entries, err)
}

func (s *Server) historyList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	if s.History == nil {
		reply(w, http.StatusOK, []history.Snapshot{}, nil)
		return
	}
	items, err := s.History.Recent(50)
	reply(w, http.StatusOK, items, err)
}

func (s *Server) historyRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	if s.History == nil {
		reply(w, http.StatusServiceUnavailable, nil, fmt.Errorf("history is not configured"))
		return
	}
	item, ok, err := s.History.Get(req.ID)
	if err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("history snapshot not found")
		}
		reply(w, http.StatusNotFound, nil, err)
		return
	}
	before, err := s.Firewall.ExportBackup()
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Firewall.RestoreBackup(ctx, item.Backup, s.Port); err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	pending, err := s.beginRollback(before, "history.restore", r)
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.audit(r, "history.restore", true, "", map[string]any{"snapshotId": req.ID})
	reply(w, http.StatusOK, map[string]any{"restored": true, "rollback": pending}, nil)
}

func (s *Server) backup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	fw, err := s.Firewall.ExportBackup()
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.mu.Lock()
	cfg := s.RuntimeConfig
	s.mu.Unlock()
	reply(w, http.StatusOK, fullBackup{
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Firewall:  fw,
		Runtime:   runtimeBackupFromConfig(cfg),
	}, nil)
}

func runtimeBackupFromConfig(cfg appconfig.Config) runtimeBackup {
	return runtimeBackup{
		PublicHost:       cfg.PublicHost,
		ListenHost:       cfg.ListenHost,
		ListenPort:       cfg.ListenPort,
		ExternalPort:     cfg.ExternalPort,
		SecureCookies:    cfg.SecureCookies,
		TLSCert:          cfg.TLSCert,
		TLSKey:           cfg.TLSKey,
		UpdateChannel:    cfg.UpdateChannel,
		AllowedCIDRs:     append([]string(nil), cfg.AllowedCIDRs...),
		RollbackSeconds:  cfg.RollbackSeconds,
		PortScanInterval: cfg.PortScanInterval,
	}
}

func applyRuntimeBackup(cfg appconfig.Config, b runtimeBackup) appconfig.Config {
	cfg.PublicHost = b.PublicHost
	cfg.ListenHost = b.ListenHost
	cfg.ListenPort = b.ListenPort
	cfg.ExternalPort = b.ExternalPort
	cfg.SecureCookies = b.SecureCookies
	cfg.TLSCert = b.TLSCert
	cfg.TLSKey = b.TLSKey
	cfg.UpdateChannel = b.UpdateChannel
	cfg.AllowedCIDRs = security.NormalizeCIDRs(b.AllowedCIDRs)
	cfg.RollbackSeconds = b.RollbackSeconds
	cfg.PortScanInterval = b.PortScanInterval
	return cfg
}

func (s *Server) restoreBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var payload fullBackup
	if err := decodeJSONLimit(w, r, &payload, 4*1024*1024); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	if payload.Version != 1 {
		reply(w, http.StatusBadRequest, nil, fmt.Errorf("unsupported backup version"))
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()

	before, err := s.Firewall.ExportBackup()
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.mu.Lock()
	oldCfg := s.RuntimeConfig
	s.mu.Unlock()
	nextCfg := applyRuntimeBackup(oldCfg, payload.Runtime)
	if err := appconfig.Validate(nextCfg); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	if len(nextCfg.AllowedCIDRs) > 0 && !security.IPAllowed(r.RemoteAddr, nextCfg.AllowedCIDRs) {
		reply(w, http.StatusBadRequest, nil, fmt.Errorf("backup would lock out the current client"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := s.Firewall.RestoreBackup(ctx, payload.Firewall, s.Port); err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	if err := appconfig.Save(s.ConfigPath, nextCfg); err != nil {
		_ = s.Firewall.RestoreBackup(ctx, before, s.Port)
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.mu.Lock()
	s.RuntimeConfig = nextCfg
	s.mu.Unlock()
	pending, err := s.beginRollbackWithConfig(before, oldCfg, "backup.restore", r)
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	restart := runtimeRestartRequired(oldCfg, nextCfg)
	s.audit(r, "backup.restore", true, "", nil)
	reply(w, http.StatusOK, map[string]any{"restored": true, "rollback": pending, "restartRequired": restart}, nil)
}

func (s *Server) advancedRules(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		rules, err := s.Firewall.AdvancedRules()
		reply(w, http.StatusOK, rules, err)
		return
	}
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req service.FirewallAdvancedRule
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	before, err := s.Firewall.ExportBackup()
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rules, err := s.Firewall.AddAdvancedRuleSafe(ctx, req, s.Port)
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	pending, err := s.beginRollback(before, "advanced.add", r)
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.audit(r, "advanced.add", true, "", map[string]any{"rule": req})
	reply(w, http.StatusOK, map[string]any{"rules": rules, "rollback": pending}, nil)
}

func (s *Server) deleteAdvancedRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	before, err := s.Firewall.ExportBackup()
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rules, err := s.Firewall.DeleteAdvancedRuleSafe(ctx, req.ID, s.Port)
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	pending, err := s.beginRollback(before, "advanced.delete", r)
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.audit(r, "advanced.delete", true, "", map[string]any{"ruleId": req.ID})
	reply(w, http.StatusOK, map[string]any{"rules": rules, "rollback": pending}, nil)
}

func (s *Server) restartService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	if s.Restart == nil {
		reply(w, http.StatusServiceUnavailable, nil, fmt.Errorf("restart is not configured"))
		return
	}
	s.audit(r, "system.restart", true, "", nil)
	reply(w, http.StatusOK, map[string]bool{"restarting": true}, nil)
	go func() {
		time.Sleep(350 * time.Millisecond)
		s.Restart()
	}()
}

func (s *Server) confirmRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	if s.Rollbacks == nil || !s.Rollbacks.Confirm(req.Token) {
		reply(w, http.StatusNotFound, nil, fmt.Errorf("rollback transaction not found or expired"))
		return
	}
	s.audit(r, "firewall.confirm", true, "", nil)
	reply(w, http.StatusOK, map[string]bool{"confirmed": true}, nil)
}

func (s *Server) beginRollback(before service.FirewallBackup, reason string, r *http.Request) (rollback.Pending, error) {
	return s.beginRollbackWithConfig(before, appconfig.Config{}, reason, r)
}

func (s *Server) beginRollbackWithConfig(before service.FirewallBackup, oldCfg appconfig.Config, reason string, r *http.Request) (rollback.Pending, error) {
	if s.Rollbacks == nil {
		s.Rollbacks = rollback.NewManager()
	}
	s.mu.Lock()
	seconds := s.RuntimeConfig.RollbackSeconds
	expectedRuntime := runtimeBackupFromConfig(s.RuntimeConfig)
	s.mu.Unlock()
	if seconds == 0 {
		seconds = 45
	}
	if s.History != nil {
		_ = s.History.Add(history.Snapshot{ID: token()[:16], Reason: reason, Backup: before})
	}
	pending, err := s.Rollbacks.Begin(before, time.Duration(seconds)*time.Second, func(snapshot service.FirewallBackup) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		restoreErr := s.Firewall.RestoreBackup(ctx, snapshot, s.Port)
		if oldCfg.ListenPort != 0 {
			restoreErr = errors.Join(restoreErr, s.restoreRuntimeAfterRollback(oldCfg, expectedRuntime))
		}
		message := ""
		if restoreErr != nil {
			message = restoreErr.Error()
		}
		if s.Audit != nil {
			_ = s.Audit.Append(audit.Entry{
				User:     s.username(),
				Action:   "firewall.rollback",
				Success:  restoreErr == nil,
				Message:  message,
				Metadata: map[string]any{"reason": reason},
			})
		}
	})
	return pending, err
}

// Authentication is excluded from runtime backups. Restore only those fields,
// and only if no later runtime edit has superseded the backup transaction.
func (s *Server) restoreRuntimeAfterRollback(old appconfig.Config, expected runtimeBackup) error {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.mu.Lock()
	current := s.RuntimeConfig
	s.mu.Unlock()
	if !reflect.DeepEqual(runtimeBackupFromConfig(current), expected) {
		return fmt.Errorf("runtime rollback skipped: newer settings were saved")
	}
	next := applyRuntimeBackup(current, runtimeBackupFromConfig(old))
	if err := appconfig.Save(s.ConfigPath, next); err != nil {
		return fmt.Errorf("restore runtime configuration: %w", err)
	}
	s.mu.Lock()
	s.RuntimeConfig = next
	s.mu.Unlock()
	return nil
}

func (s *Server) audit(r *http.Request, action string, success bool, message string, metadata map[string]any) {
	if s.Audit == nil {
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	_ = s.Audit.Append(audit.Entry{
		User:     s.username(),
		RemoteIP: host,
		Action:   action,
		Success:  success,
		Message:  message,
		Metadata: metadata,
	})
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, target any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request must contain one JSON object")
	}
	return nil
}

func defaultDataPaths(statePath string) (auditPath, historyPath string) {
	dir := filepath.Dir(statePath)
	return filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "history.jsonl")
}

func trimAddress(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return strings.Trim(address, "[]")
}
