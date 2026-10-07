package service

import "testing"

func TestParseContainerPorts(t *testing.T) {
	row := containerPSRow{
		ID:    "abc123",
		Names: "web",
		Image: "nginx:latest",
		Ports: "0.0.0.0:8443->443/tcp, 127.0.0.1:5353->53/udp, :::8080->80/tcp",
	}
	got := parseContainerPorts("docker", row)
	if len(got) != 3 {
		t.Fatalf("ports = %d, want 3: %#v", len(got), got)
	}
	if !got[0].Public || got[0].HostPort != 8443 || got[0].ContainerPort != 443 {
		t.Fatalf("unexpected public mapping: %#v", got[0])
	}
	if got[1].Public || got[1].Protocol != "udp" {
		t.Fatalf("unexpected loopback mapping: %#v", got[1])
	}
	if !got[2].Public || got[2].HostPort != 8080 {
		t.Fatalf("unexpected IPv6 mapping: %#v", got[2])
	}
}
