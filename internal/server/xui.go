package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
	"github.com/SawaMEN/Firewall-UI/internal/service"
)

type xuiRequest struct {
	Enabled    bool   `json:"enabled"`
	URL        string `json:"url"`
	Token      string `json:"token"`
	ClearToken bool   `json:"clearToken"`
}

func applyXUIRequest(old service.XUIConfig, req xuiRequest) service.XUIConfig {
	old.Enabled, old.URL = req.Enabled, strings.TrimRight(strings.TrimSpace(req.URL), "/")
	if req.ClearToken {
		old.Token = ""
	}
	if req.Token != "" {
		old.Token = strings.TrimSpace(req.Token)
	}
	return old
}

func (s *Server) xuiView() any {
	s.mu.Lock()
	cfg := s.RuntimeConfig.XUI
	s.mu.Unlock()
	return struct {
		Enabled         bool              `json:"enabled"`
		URL             string            `json:"url"`
		TokenConfigured bool              `json:"tokenConfigured"`
		Status          service.XUIStatus `json:"status"`
	}{cfg.Enabled, cfg.URL, cfg.Token != "", s.XUI.Status()}
}

func (s *Server) xuiSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		reply(w, http.StatusOK, s.xuiView(), nil)
		return
	}
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req xuiRequest
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.mu.Lock()
	cfg := s.RuntimeConfig
	s.mu.Unlock()
	cfg.XUI = applyXUIRequest(cfg.XUI, req)
	if err := service.ValidateXUIConfig(cfg.XUI); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	if s.ConfigPath == "" {
		reply(w, http.StatusConflict, nil, fmt.Errorf("configuration file is not configured"))
		return
	}
	if err := appconfig.Save(s.ConfigPath, cfg); err != nil {
		reply(w, http.StatusOK, nil, err)
		return
	}
	s.mu.Lock()
	s.RuntimeConfig = cfg
	s.mu.Unlock()
	s.XUI.Configure(cfg.XUI)
	reply(w, http.StatusOK, s.xuiView(), nil)
}

func (s *Server) xuiTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req xuiRequest
	if err := decode(w, r, &req); err != nil {
		reply(w, http.StatusBadRequest, nil, err)
		return
	}
	s.mu.Lock()
	old := s.RuntimeConfig.XUI
	s.mu.Unlock()
	cfg := applyXUIRequest(old, req)
	cfg.Enabled = true
	inbounds, err := s.XUI.Fetch(r.Context(), cfg)
	reply(w, http.StatusOK, map[string]any{"connected": err == nil, "inbounds": len(inbounds)}, err)
}
