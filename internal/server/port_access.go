package server

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func (s *Server) setPortAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, 405, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Closed   *bool  `json:"closed"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, 400, nil, err)
		return
	}
	if req.Closed == nil {
		reply(w, 400, nil, fmt.Errorf("closed is required"))
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if !s.requireNoPendingRollback(w) {
		return
	}
	before, err := s.Firewall.ExportBackup()
	if err != nil {
		reply(w, 200, nil, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Firewall.RememberSafetyPort(s.Port); err != nil {
		reply(w, 200, nil, err)
		return
	}
	if err := s.Firewall.MarkControlInitialized(); err != nil {
		reply(w, 200, nil, err)
		return
	}
	rules, err := s.Firewall.SetPortClosedSafe(ctx, req.Port, req.Protocol, *req.Closed, s.Port)
	if err != nil {
		reply(w, 200, nil, err)
		return
	}
	if !*req.Closed {
		if _, err := s.Firewall.AddManagedManualRuleSafe(ctx, req.Port, req.Protocol, "Открыт вручную", s.Port); err != nil {
			_ = s.Firewall.RestoreBackup(ctx, before, s.Port)
			reply(w, 200, nil, err)
			return
		}
	}
	pending, err := s.beginRollback(before, "port.access", r)
	if err != nil {
		_ = s.Firewall.RestoreBackup(ctx, before, s.Port)
		reply(w, 200, nil, err)
		return
	}
	s.audit(r, "port.access", true, "", map[string]any{"port": req.Port, "protocol": req.Protocol, "closed": *req.Closed})
	reply(w, 200, map[string]any{"rules": rules, "rollback": pending}, nil)
}
