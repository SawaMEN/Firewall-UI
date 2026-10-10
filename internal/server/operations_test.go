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

func TestOverviewCoverageUsesFullRangesAndExactProtocols(t *testing.T) {
	ports := []service.Port{
		{Port: 65000, Protocol: "tcp", Listening: true},
		{Port: 65000, Protocol: "udp", Listening: true},
		{Port: 8081, Protocol: "udp", Listening: true},
		{Port: 9000, Protocol: "tcp", Listening: true},
		{Port: 9001, Protocol: "tcp", Listening: true},
		{Port: 443, Protocol: "tcp", Listening: false},
	}
	basic := []service.FirewallRule{
		{PortRange: "8080-8082", Protocol: "udp", Exists: true},
		{Port: 9001, Protocol: "tcp", Exists: false},
	}
	advanced := []service.FirewallAdvancedRule{
		{Action: "allow", Protocol: "tcp", PortStart: 10000, PortEnd: 65535},
		{Action: "deny", Protocol: "tcp", PortStart: 9000, PortEnd: 9000},
	}
	covered := coveredListeningPorts(ports, true, basic, advanced)
	if len(covered) != 2 || !covered["65000/tcp"] || !covered["8081/udp"] {
		t.Fatalf("range or protocol coverage is incorrect: %v", covered)
	}
	if len(coveredListeningPorts(ports, false, basic, advanced)) != 0 {
		t.Fatal("disabled firewall reports covered ports")
	}
	advanced = []service.FirewallAdvancedRule{{Action: "allow", Protocol: "any", PortStart: 64000, PortEnd: 65535}}
	covered = coveredListeningPorts(ports, true, nil, advanced)
	if len(covered) != 2 || !covered["65000/tcp"] || !covered["65000/udp"] {
		t.Fatalf("ANY range does not cover both protocols: %v", covered)
	}
}
