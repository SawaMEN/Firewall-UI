package server

import (
	"github.com/SawaMEN/Firewall-UI/internal/service"
	"testing"
	"time"
)

func TestActivePortStreamIgnoresTransientConnections(t *testing.T) {
	active := service.Port{Port: 443, Protocol: "tcp", SocketID: "listener", Listening: true, Processes: []service.Process{{PID: 42, Name: "server"}}}
	snapshot := service.PortSnapshot{Ports: []service.Port{active}, Containers: []service.ContainerPort{}, UpdatedAt: time.Now()}
	_, initial := portStreamState(snapshot, true)
	snapshot.UpdatedAt = snapshot.UpdatedAt.Add(time.Second)
	snapshot.Ports = append(snapshot.Ports, service.Port{Port: 53212, Protocol: "tcp", SocketID: "temporary"}, service.Port{Port: 9000, Listening: true})
	filtered, unchanged := portStreamState(snapshot, true)
	if initial != unchanged || len(filtered.Ports) != 1 || len(snapshot.Ports) != 3 {
		t.Fatal("hidden sockets or timestamps changed active stream, or source was mutated")
	}
	_, diagnostic := portStreamState(snapshot, false)
	if diagnostic == initial {
		t.Fatal("diagnostic stream lost transient sockets")
	}
	snapshot.Ports[0].Port = 8443
	_, changed := portStreamState(snapshot, true)
	if changed == unchanged {
		t.Fatal("active port change was suppressed")
	}
	snapshot.Containers = []service.ContainerPort{{HostPort: 9000, Runtime: "docker"}}
	_, container := portStreamState(snapshot, true)
	if container == changed {
		t.Fatal("container publication change was suppressed")
	}
}
