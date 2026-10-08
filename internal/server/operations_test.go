package server

import (
	"testing"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
	"github.com/SawaMEN/Firewall-UI/internal/service"
)

func TestOverviewCountsBeyondRiskPreview(t *testing.T) {
	ports := make([]service.Port, 60)
	for i := range ports {
		ports[i] = service.Port{Port: 1000 + i, Protocol: "tcp", Address: "0.0.0.0", Listening: true}
	}
	ports = append(ports, service.Port{Address: "127.0.0.1", Listening: true}, service.Port{Address: "0.0.0.0"})
	listening, public, risky := summarizePorts(ports, map[string]bool{"1000/tcp": true})
	if listening != 61 || public != 60 || len(risky) != 30 || risky[0].Port != 1001 {
		t.Fatalf("incorrect totals/preview: listening=%d public=%d risky=%v", listening, public, risky)
	}
}

func TestBackupRuntimeRestartChanges(t *testing.T) {
	base := appconfig.Config{ListenHost: "127.0.0.1", ListenPort: 8088, PortScanInterval: 2}
	if runtimeRestartRequired(base, base) {
		t.Fatal("unchanged configuration requires restart")
	}
	changes := []func(*appconfig.Config){
		func(c *appconfig.Config) { c.TLSCert = "/cert.pem" },
		func(c *appconfig.Config) { c.TLSKey = "/key.pem" },
		func(c *appconfig.Config) { c.ExternalPort = 443 },
		func(c *appconfig.Config) { c.SecureCookies = true },
		func(c *appconfig.Config) { c.ListenHost = "0.0.0.0" },
		func(c *appconfig.Config) { c.ListenPort = 8089 },
		func(c *appconfig.Config) { c.PortScanInterval = 5 },
	}
	for i, change := range changes {
		next := base
		change(&next)
		if !runtimeRestartRequired(base, next) {
			t.Fatalf("runtime change %d missed", i)
		}
	}
	policy := base
	policy.UpdateChannel = "dev"
	if runtimeRestartRequired(base, policy) {
		t.Fatal("hot update channel change requires restart")
	}
}
