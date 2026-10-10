package service

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Process struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Executable string `json:"executable,omitempty"`
}
type Port struct {
	SocketID  string    `json:"socketId"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	Address   string    `json:"address"`
	Family    string    `json:"family"`
	State     string    `json:"state"`
	Listening bool      `json:"listening"`
	Loopback  bool      `json:"loopback"`
	Processes []Process `json:"processes"`
	Inode     string    `json:"-"`
}

var socketStates = map[string]string{"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "UNCONNECTED", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV"}

// ReadPorts reads every local TCP/UDP socket in the service's network namespace,
// and maps socket inodes to every owning process, including shared descriptors.
func ReadPorts(root string) ([]Port, error) {
	ports := []Port{}
	networkDir := filepath.Join(root, "net")
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		file, err := os.Open(filepath.Join(networkDir, table))
		if os.IsNotExist(err) && strings.HasSuffix(table, "6") {
			continue
		}
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Scan()
		for scanner.Scan() {
			p, err := parseSocket(scanner.Text(), table)
			if err != nil {
				file.Close()
				return nil, err
			}
			if p.Port != 0 {
				ports = append(ports, p)
			}
		}
		err = scanner.Err()
		file.Close()
		if err != nil {
			return nil, err
		}
	}
	if len(ports) == 0 {
		return ports, nil
	}
	wanted := make(map[string]bool, len(ports))
	for _, port := range ports {
		if port.Inode != "0" {
			wanted[port.Inode] = true
		}
	}
	owners := map[string][]Process{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		var process *Process
		seen := map[string]bool{}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if wanted[inode] && !seen[inode] {
				if process == nil {
					name, _ := os.ReadFile(filepath.Join(dir, "comm"))
					exe, _ := os.Readlink(filepath.Join(dir, "exe"))
					process = &Process{pid, strings.TrimSpace(string(name)), exe}
				}
				owners[inode] = append(owners[inode], *process)
				seen[inode] = true
			}
		}
	}
	for i := range ports {
		ports[i].Processes = owners[ports[i].Inode]
		if ports[i].Processes == nil {
			ports[i].Processes = []Process{}
		}
		sort.Slice(ports[i].Processes, func(a, b int) bool { return ports[i].Processes[a].PID < ports[i].Processes[b].PID })
	}
	sort.Slice(ports, func(i, j int) bool {
		a, b := ports[i], ports[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.Inode < b.Inode
	})
	return ports, nil
}
func parseSocket(line, table string) (Port, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return Port{}, errors.New("invalid socket table row")
	}
	endpoint := strings.Split(fields[1], ":")
	if len(endpoint) != 2 {
		return Port{}, errors.New("invalid socket endpoint")
	}
	port, err := strconv.ParseUint(endpoint[1], 16, 16)
	if err != nil {
		return Port{}, err
	}
	raw, err := hex.DecodeString(endpoint[0])
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return Port{}, fmt.Errorf("invalid socket address: %s", endpoint[0])
	}
	// Linux procfs prints each 32-bit address word in host byte order (little endian on supported release architectures).
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+3] = raw[i+3], raw[i]
		raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
	}
	ip := net.IP(raw)
	protocol := strings.TrimSuffix(table, "6")
	family := "IPv4"
	if len(raw) == 16 {
		family = "IPv6"
	}
	listening := protocol == "tcp" && fields[3] == "0A" || protocol == "udp" && fields[3] == "07"
	return Port{SocketID: fields[1] + "-" + fields[2] + "-" + fields[9], Port: int(port), Protocol: protocol, Address: ip.String(), Family: family, State: socketStates[fields[3]], Listening: listening, Loopback: ip.IsLoopback(), Processes: []Process{}, Inode: fields[9]}, nil
}
