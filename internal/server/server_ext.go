package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
	"github.com/SawaMEN/Firewall-UI/internal/audit"
	"github.com/SawaMEN/Firewall-UI/internal/history"
	"github.com/SawaMEN/Firewall-UI/internal/rollback"
	"github.com/SawaMEN/Firewall-UI/internal/security"
	"github.com/SawaMEN/Firewall-UI/internal/service"
	"github.com/SawaMEN/Firewall-UI/internal/updater"
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
	ActivePorts     []service.Port          `json:"activePorts"`
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

func (s *Server) handleExtendedAPI(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/ports/stream":
		s.streamPorts(w, r)
	case "/api/security/credentials":
		s.credentials(w, r)
	case "/api/firewall/port":
		s.setPortAccess(w, r)
	case "/api/dashboard":
		s.dashboard(w, r)
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
	case "/api/firewall/zones":
		s.firewallZones(w, r)
	case "/api/firewall/containers":
		s.firewallContainers(w, r)
	case "/api/firewall/analyze":
		s.firewallAnalysis(w, r)
	case "/api/firewall/inspect":
		s.firewallInspect(w, r)
	case "/api/firewall/traffic":
		s.firewallTraffic(w, r)
	case "/api/firewall/advanced/delete":
		s.deleteAdvancedRule(w, r)
	case "/api/firewall/unknown/delete":
		s.deleteUnknownFirewallRule(w, r)
	case "/api/firewall/rollback/confirm":
		s.confirmRollback(w, r)
	case "/api/system/restart":
		s.restartService(w, r)
	default:
		return false
	}
	return true
}

// Fingerprint only the data visible to this stream, not scan timestamps or
// transient connections excluded from the default active-port view.
func activePortSnapshot(snapshot service.PortSnapshot) service.PortSnapshot {
	ports := make([]service.Port, 0, len(snapshot.Ports))
	for _, port := range snapshot.Ports {
		if port.Listening {
			ports = append(ports, port)
		}
	}
	snapshot.Ports = ports
	return snapshot
}

func portStreamState(snapshot service.PortSnapshot, activeOnly bool) (service.PortSnapshot, [32]byte) {
	if activeOnly {
		snapshot = activePortSnapshot(snapshot)
	}
	data, _ := json.Marshal(struct {
		Ports      []service.Port
		Containers []service.ContainerPort
	}{snapshot.Ports, snapshot.Containers})
	return snapshot, sha256.Sum256(data)
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
	cookie, _ := r.Cookie(s.sessionCookieName(r))
	validSession := func() bool {
		if cookie == nil {
			return false
		}
		s.mu.Lock()
		session, ok := s.sessions[cookie.Value]
		s.mu.Unlock()
		return ok && time.Now().Before(session.expires)
	}
	activeOnly := r.URL.Query().Get("active") == "1"
	var lastState [32]byte
	var sent bool
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
			current, state := portStreamState(snapshot, activeOnly)
			if sent && state == lastState {
				continue
			}
			sent, lastState = true, state
			raw, _ := json.Marshal(current)
			if _, err := fmt.Fprintf(w, "event: ports\ndata: %s\n\n", raw); err != nil {
				return
			}
			flusher.Flush()
		case <-keepAlive.C:
			if !validSession() {
				return
			}
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
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

	covered := coveredListeningPorts(snapshot.Ports, status.Enabled, status.Rules, advanced)

	listening, public, risky := summarizePorts(snapshot.Ports, covered)
	reply(w, http.StatusOK, dashboardResponse{
		ActivePorts:     activePortSnapshot(snapshot).Ports,
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
		ip := net.ParseIP(port.Address)
		isPublic := ip != nil && !ip.IsLoopback()
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
	return old.PublicHost != next.PublicHost || old.TLSCert != next.TLSCert || old.TLSKey != next.TLSKey || old.ListenHost != next.ListenHost || old.ListenPort != next.ListenPort || old.ExternalPort != next.ExternalPort || old.SecureCookies != next.SecureCookies || old.PortScanInterval != next.PortScanInterval
}

func uniqueContainers(ports []service.ContainerPort) int {
	seen := map[string]bool{}
	for _, item := range ports {
		seen[item.Runtime+":"+item.ContainerID] = true
	}
	return len(seen)
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
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if !s.requireNoPendingRollback(w) {
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
		err = s.recoverFirewallChange(before, err, r)
		reply(w, http.StatusOK, nil, err)
		return
	}
	pending, err := s.beginRollback(before, "history.restore", r)
	if err != nil {
		err = s.recoverFirewallChange(before, err, r)
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
	s.configMu.Lock()
	defer s.configMu.Unlock()
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
	cfg.AllowedCIDRs = append([]string(nil), b.AllowedCIDRs...)
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
	if err := service.ValidateFirewallBackup(payload.Firewall); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()

	if !s.requireNoPendingRollback(w) {
		return
	}
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
	nextCfg.AllowedCIDRs = security.NormalizeCIDRs(nextCfg.AllowedCIDRs)
	if len(nextCfg.AllowedCIDRs) > 0 && !security.IPAllowed(r.RemoteAddr, nextCfg.AllowedCIDRs) {
		reply(w, http.StatusBadRequest, nil, fmt.Errorf("backup would lock out the current client"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	if err := s.Firewall.RestoreBackup(ctx, payload.Firewall, s.Port); err != nil {
		err = s.recoverFirewallChange(before, err, r)
		reply(w, http.StatusOK, nil, err)
		return
	}
	if err := appconfig.Save(s.ConfigPath, nextCfg); err != nil {
		err = s.recoverFirewallChange(before, err, r)
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.mu.Lock()
	s.RuntimeConfig = nextCfg
	s.mu.Unlock()
	pending, err := s.beginRollbackWithConfig(before, oldCfg, "backup.restore", r)
	if err != nil {
		err = s.recoverFirewallChange(before, err, r)
		err = errors.Join(err, s.restoreRuntimeAfterRollbackLocked(oldCfg, runtimeBackupFromConfig(nextCfg)))
		reply(w, http.StatusOK, nil, err)
		return
	}
	restart := runtimeRestartRequired(oldCfg, nextCfg)
	s.audit(r, "backup.restore", true, "", nil)
	reply(w, http.StatusOK, map[string]any{"restored": true, "rollback": pending, "restartRequired": restart}, nil)
}

func (s *Server) advancedRules(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		rules, err := s.Firewall.AdvancedRulesLive(ctx)
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
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if !s.requireNoPendingRollback(w) {
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
		err = s.recoverFirewallChange(before, err, r)
		reply(w, http.StatusOK, nil, err)
		return
	}
	pending, err := s.beginRollback(before, "advanced.add", r)
	if err != nil {
		err = s.recoverFirewallChange(before, err, r)
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
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if !s.requireNoPendingRollback(w) {
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
		err = s.recoverFirewallChange(before, err, r)
		reply(w, http.StatusOK, nil, err)
		return
	}
	pending, err := s.beginRollback(before, "advanced.delete", r)
	if err != nil {
		err = s.recoverFirewallChange(before, err, r)
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.audit(r, "advanced.delete", true, "", map[string]any{"ruleId": req.ID})
	reply(w, http.StatusOK, map[string]any{"rules": rules, "rollback": pending}, nil)
}

// External host rules are not part of Firewall-UI backup/rollback state.
// The service therefore deletes only an exact, freshly observed, safe rule,
// and verifies its disappearance. Never run a managed backup restoration after
// this operation, as that does not restore unrelated administrator entries.
func (s *Server) deleteUnknownFirewallRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req struct {
		Raw string `json:"raw"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if !s.requireNoPendingRollback(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Firewall.DeleteUnknownRuleSafe(ctx, req.Raw, s.Port); err != nil {
		s.audit(r, "firewall.unknown.delete", false, err.Error(), nil)
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.audit(r, "firewall.unknown.delete", true, "", map[string]any{"rule": req.Raw})
	reply(w, http.StatusOK, map[string]bool{"deleted": true}, nil)
}

func (s *Server) restartService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if !s.requireNoPendingRollback(w) {
		return
	}
	if s.Restart == nil {
		reply(w, http.StatusServiceUnavailable, nil, fmt.Errorf("restart is not configured"))
		return
	}
	s.restartUntil = time.Now().Add(2 * time.Second)
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

// The request context may already be cancelled when a command fails. Recovery
// must get its own deadline and report errors instead of silently discarding them.
func (s *Server) recoverFirewallChange(before service.FirewallBackup, cause error, r *http.Request) error {
	if errors.Is(cause, service.ErrInvalidFirewallChange) {
		return cause
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	err := s.Firewall.RestoreBackup(ctx, before, s.Port)
	if err != nil {
		cause = errors.Join(cause, fmt.Errorf("restore failed firewall change: %w", err))
	}
	s.audit(r, "firewall.change.failed", false, cause.Error(), nil)
	return cause
}

func (s *Server) beginRollback(before service.FirewallBackup, reason string, r *http.Request) (rollback.Pending, error) {
	return s.beginRollbackWithConfig(before, appconfig.Config{}, reason, r)
}

// Automatic updates use the same configuration lock and rollback guards as
// manual updates. A dev update must not terminate a pending recovery timer.
func (s *Server) ApplyAutomaticUpdate(ctx context.Context, channel string) (updater.Status, error) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.mu.Lock()
	selected := s.RuntimeConfig.UpdateChannel
	s.mu.Unlock()
	if selected != channel || channel != "dev" {
		return updater.Status{}, errors.New("automatic update channel changed")
	}
	if s.Updater == nil || s.Updater.InProgress() || time.Now().Before(s.restartUntil) || (s.Rollbacks != nil && s.Rollbacks.HasPending()) {
		return updater.Status{}, errors.New("automatic update postponed: maintenance or rollback pending")
	}
	return s.Updater.Apply(ctx, channel)
}

func (s *Server) requireNoPendingRollback(w http.ResponseWriter) bool {
	updating := s.Updater != nil && s.Updater.InProgress()
	if s.DockerUpdater != nil {
		status := updater.Status{}
		s.DockerUpdater.ReadStatus(&status)
		updating = updating || status.Applying
	}
	if time.Now().Before(s.restartUntil) || updating {
		reply(w, http.StatusConflict, nil, fmt.Errorf("Дождитесь завершения обновления или перезапуска панели"))
		return false
	}

	if s.Rollbacks != nil && s.Rollbacks.HasPending() {
		reply(w, http.StatusConflict, nil, fmt.Errorf("Дождитесь подтверждения предыдущего изменения файрволла"))
		return false
	}
	return true
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
		s.configMu.Lock()
		defer s.configMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		restoreErr := s.Firewall.RestoreBackup(ctx, snapshot, s.Port)
		if oldCfg.ListenPort != 0 {
			restoreErr = errors.Join(restoreErr, s.restoreRuntimeAfterRollbackLocked(oldCfg, expectedRuntime))
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

// Credentials are excluded from runtime backups. Restore only runtime fields,
// and only if no later runtime edit has superseded the backup transaction.
func (s *Server) restoreRuntimeAfterRollbackLocked(old appconfig.Config, expected runtimeBackup) error {
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
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request must contain one JSON object")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return fmt.Errorf("request must contain a JSON object")
	}
	object := json.NewDecoder(bytes.NewReader(raw))
	object.DisallowUnknownFields()
	return object.Decode(target)
}
