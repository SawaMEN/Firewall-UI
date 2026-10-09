package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestXUIMetadataMatchesOnlyLocalCoreSockets(t *testing.T) {
	var calls atomic.Int32
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/secret/panel/api/inbounds/options" || r.Header.Get("Authorization") != "Bearer test-secret" || r.Method != "GET" {
			t.Errorf("wrong request: %s", r.URL.Path)
			w.WriteHeader(401)
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"obj":[{"id":1,"remark":"VPN","protocol":"vless","port":443,"enable":true,"network":"ws","security":"tls"},{"id":2,"port":443,"enable":true,"nodeId":7},{"id":3,"port":443,"enable":false},{"id":4,"port":443,"enable":true,"originNodeGuid":"remote"},{"id":5,"remark":"Local","port":8080,"enable":true,"listen":"127.0.0.1","protocol":"vless"}]}`))
	}))
	defer panel.Close()
	x := NewXUIIntegration()
	x.Configure(XUIConfig{Enabled: true, URL: panel.URL + "/secret", Token: "test-secret"})
	x.refresh(context.Background())
	ports := []Port{
		{Port: 443, Protocol: "tcp", Address: "0.0.0.0", Listening: true, Processes: []Process{{Name: "xray", PID: 1}}},
		{Port: 443, Protocol: "udp", Address: "0.0.0.0", Listening: true, Processes: []Process{{Name: "xray", PID: 1}}},
		{Port: 443, Protocol: "tcp", Listening: true, Processes: []Process{{Name: "nginx", PID: 2}}},
		{Port: 443, Protocol: "tcp", Processes: []Process{{Name: "xray", PID: 1}}},
		{Port: 8080, Protocol: "tcp", Address: "10.0.0.1", Listening: true, Processes: []Process{{Name: "sing-box", PID: 3}}},
		{Port: 8080, Protocol: "tcp", Address: "127.0.0.1", Listening: true, Processes: []Process{{Name: "sing-box", PID: 3}}},
	}
	status := x.Annotate(ports)
	x.Annotate(ports)
	if calls.Load() != 1 || !status.Connected || status.Inbounds != 2 {
		t.Fatal("metadata was not cached or remote/disabled inbounds were included")
	}
	if len(ports[0].Services) != 1 || ports[0].Services[0].Name != "VPN" || ports[0].Services[0].Security != "tls" || len(ports[5].Services) != 1 {
		t.Fatal("local services were not identified")
	}
	for _, index := range []int{1, 2, 3, 4} {
		if len(ports[index].Services) != 0 {
			t.Fatalf("unrelated socket attributed: %d", index)
		}
	}
	x.Configure(XUIConfig{})
	x.Annotate(ports)
	if len(ports[0].Services) != 0 || x.Status().Enabled {
		t.Fatal("disabled integration retained annotations")
	}
}

func TestXUILegacyFallbackDiscardsSecrets(t *testing.T) {
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "options") {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"obj":[{"id":1,"port":443,"protocol":"vless","enable":true,"settings":"client-secret","streamSettings":"{\"network\":\"tcp\",\"security\":\"reality\",\"privateKey\":\"private-secret\"}"}]}`))
	}))
	defer panel.Close()
	rows, err := NewXUIIntegration().Fetch(context.Background(), XUIConfig{Enabled: true, URL: panel.URL, Token: "secret"})
	if err != nil || len(rows) != 1 || rows[0].Network != "tcp" || rows[0].Security != "reality" {
		t.Fatalf("compatibility response failed: %v", err)
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "privateKey") {
		t.Fatal("credentials leaked into catalog")
	}
}

func TestXUIAuthAndRedirectFailuresDoNotFallbackOrLeakTokens(t *testing.T) {
	for _, code := range []int{401, 403, 302} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var calls atomic.Int32
			panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "/other")
				w.WriteHeader(code)
				_, _ = w.Write([]byte("secret-token"))
			}))
			defer panel.Close()
			_, err := NewXUIIntegration().Fetch(context.Background(), XUIConfig{Enabled: true, URL: panel.URL, Token: "secret-token"})
			if err == nil || calls.Load() != 1 || strings.Contains(err.Error(), "secret-token") {
				t.Fatal("auth error followed a redirect, retried or leaked a token")
			}
		})
	}
}

func TestXUIRejectsResponseFromReplacedConfiguration(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-finish
		_, _ = w.Write([]byte(`{"success":true,"obj":[]}`))
	}))
	defer panel.Close()
	x := NewXUIIntegration()
	x.Configure(XUIConfig{Enabled: true, URL: panel.URL, Token: "secret"})
	done := make(chan struct{})
	go func() { x.refresh(context.Background()); close(done) }()
	<-started
	x.Configure(XUIConfig{})
	close(finish)
	<-done
	if x.Status().Connected || x.Status().Enabled {
		t.Fatal("old response replaced disabled connection")
	}
}
