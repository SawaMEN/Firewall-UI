package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type XUIConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Token   string `json:"token,omitempty"`
}

func ValidateXUIConfig(cfg XUIConfig) error {
	if cfg.URL != "" {
		u, err := url.Parse(cfg.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("3X-UI: укажите HTTP/HTTPS адрес панели с её базовым путём, без логина, query и fragment")
		}
	}
	if strings.ContainsAny(cfg.Token, "\r\n") || len(cfg.Token) > 2048 {
		return errors.New("3X-UI: некорректный API-токен")
	}
	if cfg.Enabled && (cfg.URL == "" || cfg.Token == "") {
		return errors.New("3X-UI: для интеграции нужны адрес панели и API-токен")
	}
	return nil
}

// Only public inbound metadata is kept. Client credentials, settings and keys
// from compatibility responses are discarded by the JSON projection.
type XUIInbound struct {
	ID             int    `json:"id"`
	Remark         string `json:"remark"`
	Protocol       string `json:"protocol"`
	Port           int    `json:"port"`
	Enable         bool   `json:"enable"`
	Listen         string `json:"listen,omitempty"`
	Network        string `json:"network,omitempty"`
	Security       string `json:"security,omitempty"`
	NodeID         *int   `json:"nodeId,omitempty"`
	OriginNodeGuid string `json:"originNodeGuid,omitempty"`
}

type PortService struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Transport string `json:"transport,omitempty"`
	Security  string `json:"security,omitempty"`
}

type XUIStatus struct {
	Enabled   bool      `json:"enabled"`
	Connected bool      `json:"connected"`
	Message   string    `json:"message,omitempty"`
	Inbounds  int       `json:"inbounds"`
	LastSync  time.Time `json:"lastSync,omitempty"`
}

type XUIIntegration struct {
	mu       sync.RWMutex
	cfg      XUIConfig
	status   XUIStatus
	inbounds []XUIInbound
	trigger  chan struct{}
	client   *http.Client
}

func NewXUIIntegration() *XUIIntegration {
	return &XUIIntegration{trigger: make(chan struct{}, 1), client: &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (x *XUIIntegration) Configure(cfg XUIConfig) {
	x.mu.Lock()
	if x.cfg == cfg {
		x.mu.Unlock()
		return
	}
	x.cfg = cfg
	x.inbounds = nil
	x.status = XUIStatus{Enabled: cfg.Enabled}
	x.mu.Unlock()
	select {
	case x.trigger <- struct{}{}:
	default:
	}
}

func (x *XUIIntegration) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-x.trigger:
				x.refresh(ctx)
			case <-ticker.C:
				x.refresh(ctx)
			}
		}
	}()
}

func (x *XUIIntegration) Status() XUIStatus { x.mu.RLock(); defer x.mu.RUnlock(); return x.status }

func (x *XUIIntegration) refresh(ctx context.Context) {
	x.mu.RLock()
	cfg := x.cfg
	x.mu.RUnlock()
	if !cfg.Enabled {
		return
	}
	inbounds, err := x.Fetch(ctx, cfg)
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.cfg != cfg {
		return
	} // Discard responses from a replaced connection.
	x.status = XUIStatus{Enabled: true, Connected: err == nil, Inbounds: len(inbounds)}
	if err != nil {
		x.status.Message = err.Error()
		x.inbounds = nil
		return
	}
	x.status.LastSync = time.Now().UTC()
	x.inbounds = inbounds
}

func (x *XUIIntegration) Fetch(ctx context.Context, cfg XUIConfig) ([]XUIInbound, error) {
	if err := ValidateXUIConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.URL == "" || cfg.Token == "" {
		return nil, errors.New("3X-UI: укажите адрес и API-токен")
	}
	// This fork offers a compact metadata endpoint. Older 3X-UI versions use
	// /list; fallback happens only on 404, never on failed authentication.
	for _, endpoint := range []string{"options", "list"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.URL, "/")+"/panel/api/inbounds/"+endpoint, nil)
		if err != nil {
			return nil, errors.New("3X-UI: некорректный адрес")
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		req.Header.Set("Accept", "application/json")
		resp, err := x.client.Do(req)
		if err != nil {
			return nil, errors.New("3X-UI: панель недоступна или сертификат не прошёл проверку")
		}
		if resp.StatusCode == http.StatusNotFound && endpoint == "options" {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				return nil, errors.New("3X-UI: API-токен неверен, отключён или истёк")
			case http.StatusForbidden:
				return nil, errors.New("3X-UI: токен не имеет доступа к инбаундам; используйте токен admin")
			case http.StatusNotFound:
				return nil, errors.New("3X-UI: проверьте базовый путь панели в адресе")
			default:
				return nil, fmt.Errorf("3X-UI: HTTP %d", resp.StatusCode)
			}
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024+1))
		resp.Body.Close()
		if err != nil || len(data) > 8*1024*1024 {
			return nil, errors.New("3X-UI: ответ слишком большой или неполный")
		}
		var envelope struct {
			Success bool              `json:"success"`
			Obj     []json.RawMessage `json:"obj"`
		}
		if json.Unmarshal(data, &envelope) != nil || !envelope.Success {
			return nil, errors.New("3X-UI: не удалось прочитать список инбаундов")
		}
		result := make([]XUIInbound, 0, len(envelope.Obj))
		for _, raw := range envelope.Obj {
			var inbound XUIInbound
			if err := json.Unmarshal(raw, &inbound); err != nil {
				return nil, errors.New("3X-UI: некорректные данные инбаунда")
			}
			if inbound.Network == "" { // Old list responses keep hints inside a JSON string.
				var legacy struct {
					StreamSettings string `json:"streamSettings"`
				}
				var hints struct {
					Network  string `json:"network"`
					Security string `json:"security"`
				}
				_ = json.Unmarshal(raw, &legacy)
				_ = json.Unmarshal([]byte(legacy.StreamSettings), &hints)
				inbound.Network, inbound.Security = hints.Network, hints.Security
			}
			if inbound.Enable && inbound.Port > 0 && inbound.Port <= 65535 && (inbound.NodeID == nil || *inbound.NodeID == 0) && inbound.OriginNodeGuid == "" {
				result = append(result, inbound)
			}
		}
		return result, nil
	}
	return nil, errors.New("3X-UI: список инбаундов не найден")
}

func xuiSocketMatches(p Port, inbound XUIInbound) bool {
	if !p.Listening || p.Port != inbound.Port {
		return false
	}
	// A matching port number alone is insufficient to attribute another service.
	core := false
	for _, proc := range p.Processes {
		name := strings.ToLower(proc.Name + " " + filepath.Base(proc.Executable))
		for _, marker := range []string{"xray", "sing-box", "singbox", "telemt", "mtproto", "hysteria", "tuic", "naive", "mieru", "snell", "shadowtls", "amnezia", "trusttunnel", "masque", "sudoku", "openflux", "fptn", "vk-turn"} {
			if strings.Contains(name, marker) {
				core = true
				break
			}
		}
	}
	if !core {
		return false
	}
	listen := strings.Trim(inbound.Listen, "[]")
	if ip := net.ParseIP(listen); ip != nil && !ip.IsUnspecified() && !ip.Equal(net.ParseIP(p.Address)) {
		return false
	}
	network := strings.ToLower(inbound.Network)
	protocol := strings.ToLower(inbound.Protocol)
	if network == "kcp" || network == "quic" || network == "udp" || protocol == "hysteria" || protocol == "hysteria2" || protocol == "tuic" || protocol == "wireguard" || protocol == "amneziawg" {
		return p.Protocol == "udp"
	}
	if network == "tcp" || network == "raw" || network == "ws" || network == "grpc" || network == "http" || network == "httpupgrade" || network == "xhttp" {
		return p.Protocol == "tcp"
	}
	return true
}

// This reads only cached data; network requests never block socket scans.
func (x *XUIIntegration) Annotate(ports []Port) XUIStatus {
	x.mu.RLock()
	defer x.mu.RUnlock()
	byPort := make(map[int][]XUIInbound, len(x.inbounds))
	for _, inbound := range x.inbounds {
		byPort[inbound.Port] = append(byPort[inbound.Port], inbound)
	}
	for i := range ports {
		ports[i].Services = nil
		for _, inbound := range byPort[ports[i].Port] {
			if xuiSocketMatches(ports[i], inbound) {
				ports[i].Services = append(ports[i].Services, PortService{ID: inbound.ID, Name: inbound.Remark, Protocol: inbound.Protocol, Transport: inbound.Network, Security: inbound.Security})
			}
		}
	}
	return x.status
}
