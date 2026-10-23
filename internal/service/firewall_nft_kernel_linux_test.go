package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests are opt-in and refuse to touch the initial network namespace.
// CI runs the compiled test binary under sudo unshare --net.
func nftKernelEnvironment(t *testing.T) (string, string) {
	t.Helper()
	if os.Getenv("FIREWALL_UI_NFT_KERNEL_TESTS") != "1" {
		t.Skip("requires disposable nftables kernel namespace")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if current == initial || os.Geteuid() != 0 {
		t.Fatal("refusing kernel firewall tests outside isolated root network namespace")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIREWALL_UI_CONTAINER", "")
	return nft, ip
}

func kernelRun(t *testing.T, binary string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", binary, args, err, out)
	}
	return string(out)
}

func kernelService(t *testing.T, nft string) *FirewallService {
	t.Helper()
	root := t.TempDir()
	// The native tests must not select the runner's installed UFW/iptables tools.
	if err := os.Symlink(nft, filepath.Join(root, "nft")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 18088, 0)
	ping := filepath.Join(root, "ping")
	if err := os.WriteFile(ping, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	previous := firewallPingSysctlPaths
	firewallPingSysctlPaths = []string{ping}
	t.Cleanup(func() { firewallPingSysctlPaths = previous })
	if err := (&SettingService{}).setBool(firewallAutoSyncKey, false); err != nil {
		t.Fatal(err)
	}
	if err := setFirewallManagedEnabledPreference(true); err != nil {
		t.Fatal(err)
	}
	managedNFTDesiredHash, managedNFTObservedHash, containerPolicyHash, containerPolicyObservedHash = [32]byte{}, [32]byte{}, [32]byte{}, [32]byte{}
	t.Cleanup(func() {
		for _, table := range []string{containerNFTTable, managedNftTable, "fwui_kernel_nat", "fwui_kernel_foreign"} {
			_ = exec.Command(nft, "delete", "table", "inet", table).Run()
		}
	})
	svc := &FirewallService{}
	if err := applyManagedNftables(context.Background(), nft, []FirewallRule{{Port: 18088, Protocol: "tcp", Source: "panel"}}); err != nil {
		t.Fatal(err)
	}
	return svc
}

func kernelEcho(t *testing.T, network, address string) (net.Addr, func()) {
	t.Helper()
	if strings.HasPrefix(network, "tcp") {
		listener, err := net.Listen(network, address)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
			}
		}()
		return listener.Addr(), func() { _ = listener.Close() }
	}
	socket, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buffer := make([]byte, 128)
		for {
			n, from, err := socket.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = socket.WriteTo(buffer[:n], from)
		}
	}()
	return socket.LocalAddr(), func() { _ = socket.Close() }
}

func kernelReachable(network, address string) bool {
	conn, err := net.DialTimeout(network, address, 250*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
	if _, err = conn.Write([]byte("probe")); err != nil {
		return false
	}
	raw := make([]byte, 5)
	_, err = io.ReadFull(conn, raw)
	return err == nil && string(raw) == "probe"
}

func TestNFTKernelInputLifecycle(t *testing.T) {
	nft, ip := nftKernelEnvironment(t)
	kernelRun(t, ip, "link", "set", "lo", "up")
	svc := kernelService(t, nft)
	ctx := context.Background()
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if strings.HasSuffix(network, "6") {
				address = "[::1]:0"
			}
			endpoint, stop := kernelEcho(t, network, address)
			defer stop()
			_, portText, _ := net.SplitHostPort(endpoint.String())
			port, _ := strconv.Atoi(portText)
			proto := network[:3]
			if !kernelReachable(network, endpoint.String()) {
				t.Fatal("baseline listener unreachable")
			}
			for _, closed := range []bool{true, true, false, true, false} {
				if _, err := svc.SetPortClosedSafe(ctx, port, proto, closed, 18088); err != nil {
					t.Fatalf("close=%v: %v", closed, err)
				}
				if got := kernelReachable(network, endpoint.String()); got == closed {
					t.Fatalf("close=%v reachable=%v", closed, got)
				}
				if closed {
					live, err := svc.AdvancedRulesLive(ctx)
					if err != nil || len(live) != 1 || live[0].Enforced == nil || !*live[0].Enforced {
						t.Fatalf("kernel close not verified: %+v %v", live, err)
					}
					// Real rule/counter snapshots, rather than command-text fixtures.
					before := kernelRun(t, nft, "-j", "list", "table", "inet", containerNFTTable)
					if err := svc.SyncContainerProtection(ctx); err != nil {
						t.Fatal(err)
					}
					after := kernelRun(t, nft, "-j", "list", "table", "inet", containerNFTTable)
					if before != after {
						t.Fatal("unchanged sync replaced kernel rules/counters")
					}
					kernelRun(t, nft, "add", "table", "inet", containerNFTTable, "{ flags dormant; }")
					if err := verifyNFTPortClose(ctx, live[0]); err == nil {
						t.Logf("dormant table JSON: %s", kernelRun(t, nft, "-j", "list", "table", "inet", containerNFTTable))
						t.Logf("dormant ruleset JSON: %s", kernelRun(t, nft, "-j", "list", "ruleset"))
						t.Fatal("dormant close table passed enforcement verification")
					}
					if _, err := svc.SetPortClosedSafe(ctx, port, proto, true, 18088); err != nil {
						t.Fatalf("dormant close repair: %v", err)
					}
				}
			}
		})
		if t.Failed() {
			return
		}
	}
	// A dormant table retains its rules and hook metadata but processes no
	// packets. Status must not treat the stored chain shape as protection.
	kernelRun(t, nft, "add", "table", "inet", managedNftTable, "{ flags dormant; }")
	dormant, err := svc.GetManagedStatusSafe(ctx, 18088)
	if err != nil || dormant.Enabled {
		t.Logf("dormant main JSON: %s", kernelRun(t, nft, "-j", "list", "table", "inet", managedNftTable))
		t.Logf("dormant ruleset JSON: %s", kernelRun(t, nft, "-j", "list", "ruleset"))
		t.Fatalf("dormant main table shown active: %+v %v", dormant, err)
	}
	if _, err := svc.SyncManagedSafe(ctx, 18088); err != nil {
		t.Fatal(err)
	}
	// Interrupted disable: saved OFF must also remove lingering owned hooks.
	if err := setFirewallManagedEnabledPreference(false); err != nil {
		t.Fatal(err)
	}
	disabled, err := svc.SyncManagedSafe(ctx, 18088)
	if err != nil || disabled.Enabled {
		t.Fatalf("saved OFF left native filtering active: %+v %v", disabled, err)
	}
	if _, err := svc.SetManagedEnabledSafe(ctx, true, 18088); err != nil {
		t.Fatal(err)
	}
	// Detached hooks and lost rules are reported from kernel evidence.
	kernelRun(t, nft, "flush", "chain", "inet", managedNftTable, managedNftChain)
	status, err := svc.GetManagedStatusSafe(ctx, 18088)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range status.Rules {
		if r.Exists {
			t.Fatal("empty kernel chain claimed active ALLOWs")
		}
	}
	if _, err := svc.SyncManagedSafe(ctx, 18088); err != nil {
		t.Fatal(err)
	}
	status, err = svc.GetManagedStatusSafe(ctx, 18088)
	if err != nil || !status.Enabled {
		t.Fatalf("native recovery failed: %+v %v", status, err)
	}
	// Genuine foreign hooks reject a change without deleting working protection.
	kernelRun(t, nft, "add", "table", "inet", "fwui_kernel_foreign")
	kernelRun(t, nft, "add", "chain", "inet", "fwui_kernel_foreign", "input", "{ type filter hook input priority 0; policy accept; }")
	before := kernelRun(t, nft, "-j", "list", "table", "inet", managedNftTable)
	if _, err := svc.SyncManagedSafe(ctx, 18088); err == nil {
		t.Fatal("foreign hook was not rejected")
	}
	after := kernelRun(t, nft, "-j", "list", "table", "inet", managedNftTable)
	if before != after {
		t.Fatal("rejected policy destroyed working table")
	}
	if _, err := svc.SetManagedEnabledSafe(ctx, false, 18088); err != nil {
		t.Fatalf("foreign hook blocked explicit disable: %v", err)
	}
	kernelRun(t, nft, "list", "table", "inet", "fwui_kernel_foreign")
	if _, err := svc.SetManagedEnabledSafe(ctx, true, 18088); err == nil {
		t.Fatal("foreign hook must still prevent native enable")
	}
	kernelRun(t, nft, "delete", "table", "inet", "fwui_kernel_foreign")
	if _, err := svc.SetManagedEnabledSafe(ctx, true, 18088); err != nil {
		t.Fatal(err)
	}
	backup, err := svc.ExportBackup()
	if err != nil {
		t.Fatal(err)
	}
	if !backup.ManagedEnabled {
		t.Fatal("backup lost enabled native state")
	}
	if _, err := svc.SetManagedEnabledSafe(ctx, false, 18088); err != nil {
		t.Fatal(err)
	}
	if err := svc.RestoreBackup(ctx, backup, 18088); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetManagedEnabledSafe(ctx, false, 18088); err != nil {
		t.Fatal(err)
	}
}

type nftKernelPeer struct {
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
}

func startNFTKernelPeer(t *testing.T, unshare, mode string) *nftKernelPeer {
	t.Helper()
	cmd := exec.Command(unshare, "--net", os.Args[0], "-test.run", "^TestNFTKernelPeer$", "-test.timeout", "90s")
	cmd.Env = append(os.Environ(), "FWUI_KERNEL_PEER="+mode)
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	peer := &nftKernelPeer{cmd: cmd, input: input, output: bufio.NewReader(output)}
	t.Cleanup(func() { _ = input.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	peer.expect(t, "WAIT")
	return peer
}
func (p *nftKernelPeer) expect(t *testing.T, want string) {
	t.Helper()
	line, err := p.output.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != want {
		t.Fatalf("peer expected %s, got %q: %v", want, line, err)
	}
}
func (p *nftKernelPeer) probe(t *testing.T, network, address string, want bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		raw, _ := json.Marshal([]string{network, address})
		_, _ = fmt.Fprintln(p.input, string(raw))
		line, err := p.output.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var got bool
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatal(err)
		}
		if got == want {
			return
		}
		if !want || time.Now().After(deadline) {
			if nft, err := exec.LookPath("nft"); err == nil {
				out, _ := exec.Command(nft, "list", "ruleset").CombinedOutput()
				t.Logf("kernel ruleset:\n%s", out)
			}
			t.Fatalf("%s %s reachable=%v want=%v", network, address, got, want)
		}
		// Initial IPv6 neighbor discovery may finish after the first probe.
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNFTKernelPeer(t *testing.T) {
	mode := os.Getenv("FWUI_KERNEL_PEER")
	if mode == "" {
		t.Skip("kernel subprocess helper")
	}
	if os.Getenv("FIREWALL_UI_NFT_KERNEL_TESTS") != "1" {
		t.Fatal("missing namespace test flag")
	}
	fmt.Println("WAIT")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() || scanner.Text() != "START" {
		t.Fatal("missing peer configuration")
	}
	if mode == "server" {
		for _, n := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
			addr := "0.0.0.0:19333"
			if strings.HasSuffix(n, "6") {
				addr = "[::]:19333"
			}
			_, stop := kernelEcho(t, n, addr)
			defer stop()
		}
		fmt.Println("READY")
		for scanner.Scan() {
		}
		return
	}
	fmt.Println("READY")
	for scanner.Scan() {
		var request []string
		if json.Unmarshal(scanner.Bytes(), &request) != nil || len(request) != 2 {
			t.Fatal("invalid probe")
		}
		fmt.Println(kernelReachable(request[0], request[1]))
	}
}

func TestNFTKernelDNATForward(t *testing.T) {
	nft, ip := nftKernelEnvironment(t)
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Fatal(err)
	}
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		t.Fatal(err)
	}
	client := startNFTKernelPeer(t, unshare, "client")
	server := startNFTKernelPeer(t, unshare, "server")
	for _, setup := range []struct {
		name, peer, a, b, ipv4, ipv6 string
		p                            *nftKernelPeer
	}{
		{"cl0", "c0", "10.75.0.1/24", "fd75::1/64", "10.75.0.2/24", "fd75::2/64", client},
		{"sv0", "s0", "10.76.0.1/24", "fd76::1/64", "10.76.0.2/24", "fd76::2/64", server},
	} {
		kernelRun(t, ip, "link", "add", setup.name, "type", "veth", "peer", "name", setup.peer)
		t.Cleanup(func() { _ = exec.Command(ip, "link", "delete", setup.name).Run() })
		kernelRun(t, ip, "addr", "add", setup.a, "dev", setup.name)
		kernelRun(t, ip, "-6", "addr", "add", setup.b, "dev", setup.name, "nodad")
		kernelRun(t, ip, "link", "set", setup.name, "up")
		pid := strconv.Itoa(setup.p.cmd.Process.Pid)
		kernelRun(t, ip, "link", "set", setup.peer, "netns", pid)
		for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", setup.ipv4, "dev", setup.peer}, {"-6", "addr", "add", setup.ipv6, "dev", setup.peer, "nodad"}, {"link", "set", setup.peer, "up"}, {"route", "add", "default", "via", strings.Split(setup.a, "/")[0]}, {"-6", "route", "add", "default", "via", strings.Split(setup.b, "/")[0]}} {
			kernelRun(t, nsenter, append([]string{"--target", pid, "--net", "--", ip}, args...)...)
		}
	}
	for _, file := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if err := os.WriteFile(file, []byte("1\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = fmt.Fprintln(client.input, "START")
	client.expect(t, "READY")
	_, _ = fmt.Fprintln(server.input, "START")
	server.expect(t, "READY")
	svc := kernelService(t, nft)
	ctx := context.Background()
	nat := `table inet fwui_kernel_nat {
 chain prerouting { type nat hook prerouting priority dstnat; policy accept;
 meta nfproto ipv4 tcp dport 19332 dnat ip to 10.76.0.2:19333
 meta nfproto ipv4 udp dport 19332 dnat ip to 10.76.0.2:19333
 meta nfproto ipv6 tcp dport 19332 dnat ip6 to [fd76::2]:19333
 meta nfproto ipv6 udp dport 19332 dnat ip6 to [fd76::2]:19333
 meta nfproto ipv4 tcp dport 18088 dnat ip to 10.76.0.2:19333
 meta nfproto ipv6 tcp dport 18088 dnat ip6 to [fd76::2]:19333
 }
}`
	cmd := exec.Command(nft, "-f", "-")
	cmd.Stdin = strings.NewReader(nat)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("DNAT: %v %s", err, out)
	}
	manual := []FirewallManualRule{{Port: 19332, Protocol: "tcp"}, {Port: 19332, Protocol: "udp"}}
	if err := saveFirewallJSON(firewallManualRulesKey, manual); err != nil {
		t.Fatal(err)
	}
	if err := (&SettingService{}).setBool(containerProtectionKey, true); err != nil {
		t.Fatal(err)
	}
	svc.PortMonitor = NewPortMonitor("/proc", time.Second)
	svc.PortMonitor.snapshot = PortSnapshot{Containers: []ContainerPort{
		{HostPort: 19332, ContainerPort: 19333, HostIP: "0.0.0.0", Protocol: "tcp", Public: true},
		{HostPort: 19332, ContainerPort: 19333, HostIP: "0.0.0.0", Protocol: "udp", Public: true},
		{HostPort: 19332, ContainerPort: 19333, HostIP: "::", Protocol: "tcp", Public: true},
		{HostPort: 19332, ContainerPort: 19333, HostIP: "::", Protocol: "udp", Public: true},
		{HostPort: 18088, ContainerPort: 19333, HostIP: "0.0.0.0", Protocol: "tcp", Public: true},
		{HostPort: 18088, ContainerPort: 19333, HostIP: "::", Protocol: "tcp", Public: true},
	}}
	if err := svc.SyncContainerProtection(ctx); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		target := "10.75.0.1:19332"
		if strings.HasSuffix(network, "6") {
			target = "[fd75::1]:19332"
		}
		client.probe(t, network, target, true)
		if _, err := svc.SetPortClosedSafe(ctx, 19332, network[:3], true, 18088); err != nil {
			t.Fatal(err)
		}
		client.probe(t, network, target, false)
		if _, err := svc.SetPortClosedSafe(ctx, 19332, network[:3], false, 18088); err != nil {
			t.Fatal(err)
		}
		client.probe(t, network, target, true)
	}
	// Freeze automatic service ALLOWs, close them and reopen without losing
	// the frozen service set from the ownership ledger.
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		bind := "10.75.0.1:19444"
		if strings.HasSuffix(network, "6") {
			bind = "[fd75::1]:19444"
		}
		endpoint, stop := kernelEcho(t, network, bind)
		ledger, err := loadManagedFirewallRules()
		if err != nil {
			t.Fatal(err)
		}
		ledger = append(ledger, FirewallRule{Port: 19444, Protocol: network[:3], Source: "service", Owned: true})
		if err := saveFirewallJSON(firewallManagedRulesKey, ledger); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.SyncManagedSafe(ctx, 18088); err != nil {
			t.Fatal(err)
		}
		client.probe(t, network, endpoint.String(), true)
		if _, err := svc.SetPortClosedSafe(ctx, 19444, network[:3], true, 18088); err != nil {
			t.Fatal(err)
		}
		client.probe(t, network, endpoint.String(), false)
		if _, err := svc.SetPortClosedSafe(ctx, 19444, network[:3], false, 18088); err != nil {
			t.Fatal(err)
		}
		client.probe(t, network, endpoint.String(), true)
		stop()
	}
	// Advanced CIDR/interface/range rules must have the same precedence in
	// actual INPUT filtering as in their saved order.
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		bind, source := "10.75.0.1:19505", "10.75.0.2/32"
		if strings.HasSuffix(network, "6") {
			bind, source = "[fd75::1]:19505", "fd75::2/128"
		}
		endpoint, stop := kernelEcho(t, network, bind)
		client.probe(t, network, endpoint.String(), false)
		allow := FirewallAdvancedRule{ID: "kernel-allow-" + network, Action: "allow", Protocol: network[:3], PortStart: 19500, PortEnd: 19510, SourceCIDR: source, Interface: "cl0", Priority: 100}
		if _, err := svc.AddAdvancedRuleSafe(ctx, allow, 18088); err != nil {
			t.Fatal(err)
		}
		client.probe(t, network, endpoint.String(), true)
		deny := allow
		deny.ID = "kernel-deny-" + network
		deny.Action = "deny"
		deny.PortStart = 19505
		deny.PortEnd = 19505
		deny.Priority = -100
		if _, err := svc.AddAdvancedRuleSafe(ctx, deny, 18088); err != nil {
			t.Fatal(err)
		}
		client.probe(t, network, endpoint.String(), false)
		if _, err := svc.DeleteAdvancedRuleSafe(ctx, deny.ID, 18088); err != nil {
			t.Fatal(err)
		}
		client.probe(t, network, endpoint.String(), true)
		if _, err := svc.DeleteAdvancedRuleSafe(ctx, allow.ID, 18088); err != nil {
			t.Fatal(err)
		}
		client.probe(t, network, endpoint.String(), false)
		stop()
	}
	// Panel/reverse-proxy access needs its own FORWARD exception. INPUT
	// ALLOWs do not preserve access when the proxy is a published container.
	broad := FirewallAdvancedRule{ID: "kernel-broad-deny", Action: "deny", Protocol: "any", IPVersion: "any", Priority: -900}
	if _, err := svc.AddAdvancedRuleSafe(ctx, broad, 18088); err != nil {
		t.Fatal(err)
	}
	traffic, err := svc.TrafficCounters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foundGlobalCounter := false
	for _, counter := range traffic.Counters {
		if counter.Rule == "fwui-advanced:kernel-broad-deny" && counter.Table == managedNftTable {
			foundGlobalCounter = true
		}
	}
	if !foundGlobalCounter {
		t.Fatal("unconditional advanced rule lost its kernel counter/identity")
	}
	probe := AccessProbe{SourceIP: "10.75.0.2", Port: 18088, Protocol: "tcp", Interface: "cl0"}
	diagnosis, err := svc.InspectAccess(ctx, 18088, probe)
	if err != nil || diagnosis.Verdict != "predicted-allow" || !strings.Contains(diagnosis.Reason, "FORWARD rule precedes") {
		t.Fatalf("protected DNAT diagnosis diverged from policy: %+v %v", diagnosis, err)
	}
	newRequestPort := probe
	newRequestPort.Port = 19332
	unprotectedDiagnosis, err := svc.InspectAccess(ctx, 19332, newRequestPort)
	if err != nil || unprotectedDiagnosis.Verdict != "predicted-deny" {
		t.Fatalf("request port invented a live FORWARD exception: %+v %v", unprotectedDiagnosis, err)
	}
	kernelRun(t, nft, "flush", "chain", "inet", containerNFTTable, "forward")
	containerStatus, err := svc.ContainerProtectionStatus(ctx)
	if err != nil || containerStatus.Active {
		t.Fatalf("flushed FORWARD shown protected: %+v %v", containerStatus, err)
	}
	diagnosis, err = svc.InspectAccess(ctx, 18088, probe)
	if err != nil || diagnosis.Verdict != "unknown" {
		t.Fatalf("flushed FORWARD guessed access: %+v %v", diagnosis, err)
	}
	if err := svc.SyncContainerProtection(ctx); err != nil {
		t.Fatal(err)
	}
	client.probe(t, "tcp4", "10.75.0.1:18088", true)
	client.probe(t, "tcp6", "[fd75::1]:18088", true)
	if _, err := svc.DeleteAdvancedRuleSafe(ctx, broad.ID, 18088); err != nil {
		t.Fatal(err)
	}
	// Broad protection without exceptions must deny new forwarded attempts.
	if err := saveFirewallJSON(firewallManualRulesKey, []FirewallManualRule{}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SyncContainerProtection(ctx); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		target := "10.75.0.1:19332"
		if strings.HasSuffix(network, "6") {
			target = "[fd75::1]:19332"
		}
		client.probe(t, network, target, false)
	}
}

func TestNFTKernelAdvancedExpressionSyntax(t *testing.T) {
	nft, _ := nftKernelEnvironment(t)
	for _, action := range []string{"allow", "deny"} {
		for _, protocol := range []string{"any", "tcp", "udp"} {
			for _, family := range []string{"any", "ipv4", "ipv6"} {
				for _, ports := range [][2]int{{0, 0}, {19000, 19000}, {19000, 19010}} {
					if protocol == "any" && ports[0] > 0 {
						continue
					}
					rule := FirewallAdvancedRule{Action: action, Protocol: protocol, IPVersion: family, PortStart: ports[0], PortEnd: ports[1], Interface: "veth-test"}
					if family == "ipv4" {
						rule.SourceCIDR = "192.0.2.0/24"
					}
					if family == "ipv6" {
						rule.SourceCIDR = "2001:db8::/64"
					}
					if err := validateAdvancedRule(&rule); err != nil {
						t.Fatal(err)
					}
					script := "table inet fwui_syntax {\n chain input {\n type filter hook input priority 100; policy drop;\n " + advancedNFTExpression(rule) + "\n }\n}\n"
					cmd := exec.Command(nft, "--check", "-f", "-")
					cmd.Stdin = strings.NewReader(script)
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("kernel rejected %s: %v %s", script, err, out)
					}
				}
			}
		}
	}
}
