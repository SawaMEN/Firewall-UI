package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/service"
)

func (s *Server) firewallZones(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if r.Method == http.MethodGet {
		zones, err := s.Firewall.FirewalldZones(ctx)
		reply(w, http.StatusOK, zones, err)
		return
	}
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req struct {
		Zone string `json:"zone"`
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
	zones, err := s.Firewall.SetFirewalldZone(ctx, req.Zone)
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	pending, err := s.beginRollback(before, "firewall.zone", r)
	if err != nil {
		err = s.recoverFirewallChange(before, err, r)
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.audit(r, "firewall.zone", true, "", map[string]any{"zone": req.Zone})
	reply(w, http.StatusOK, map[string]any{"zones": zones, "rollback": pending}, nil)
}

func (s *Server) firewallContainers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if r.Method == http.MethodGet {
		status, err := s.Firewall.ContainerProtectionStatus(ctx)
		reply(w, http.StatusOK, status, err)
		return
	}
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	if req.Enabled == nil {
		reply(w, http.StatusBadRequest, nil, fmt.Errorf("enabled is required"))
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
	if err = s.Firewall.SetContainerProtection(ctx, *req.Enabled); err != nil {
		reply(w, http.StatusOK, nil, s.recoverFirewallChange(before, err, r))
		return
	}
	pending, err := s.beginRollback(before, "firewall.containers", r)
	if err != nil {
		reply(w, http.StatusOK, nil, s.recoverFirewallChange(before, err, r))
		return
	}
	status, err := s.Firewall.ContainerProtectionStatus(ctx)
	if err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.audit(r, "firewall.containers", true, "", map[string]any{"enabled": *req.Enabled})
	reply(w, http.StatusOK, map[string]any{"status": status, "rollback": pending}, nil)
}

func (s *Server) firewallAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	analysis, err := s.Firewall.InspectRules(ctx, s.Port)
	reply(w, http.StatusOK, analysis, err)
}

func (s *Server) firewallInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req service.AccessProbe
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	diagnosis, err := s.Firewall.InspectAccess(ctx, s.Port, req)
	if err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	reply(w, http.StatusOK, diagnosis, nil)
}

func (s *Server) firewallTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	counters, err := s.Firewall.TrafficCounters(ctx)
	reply(w, http.StatusOK, counters, err)
}
