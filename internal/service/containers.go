package service

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ContainerPort struct {
	Runtime       string `json:"runtime"`
	ContainerID   string `json:"containerId"`
	ContainerName string `json:"containerName"`
	Image         string `json:"image"`
	HostIP        string `json:"hostIp"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	Public        bool   `json:"public"`
}

type containerPSRow struct {
	ID    string `json:"ID"`
	Names string `json:"Names"`
	Image string `json:"Image"`
	Ports string `json:"Ports"`
}

func ReadContainerPorts(ctx context.Context) []ContainerPort {
	out := make([]ContainerPort, 0)
	for _, runtime := range []string{"docker", "podman"} {
		path, err := exec.LookPath(runtime)
		if err != nil {
			continue
		}
		commandCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		cmd := exec.CommandContext(commandCtx, path, "ps", "--format", "{{json .}}")
		raw, err := cmd.Output()
		cancel()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(raw)))
		for scanner.Scan() {
			var row containerPSRow
			if json.Unmarshal(scanner.Bytes(), &row) != nil {
				continue
			}
			out = append(out, parseContainerPorts(runtime, row)...)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].HostPort != out[j].HostPort {
			return out[i].HostPort < out[j].HostPort
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].ContainerName < out[j].ContainerName
	})
	return out
}

func parseContainerPorts(runtime string, row containerPSRow) []ContainerPort {
	out := []ContainerPort{}
	for _, segment := range strings.Split(row.Ports, ",") {
		segment = strings.TrimSpace(segment)
		arrow := strings.Index(segment, "->")
		if arrow < 0 {
			continue
		}
		left := strings.TrimSpace(segment[:arrow])
		right := strings.TrimSpace(segment[arrow+2:])
		proto := "tcp"
		if slash := strings.LastIndex(right, "/"); slash >= 0 {
			proto = strings.ToLower(strings.TrimSpace(right[slash+1:]))
			right = right[:slash]
		}
		containerPort, err := strconv.Atoi(strings.TrimSpace(right))
		if err != nil {
			continue
		}

		host, portText, err := net.SplitHostPort(left)
		if err != nil {
			if idx := strings.LastIndex(left, ":"); idx >= 0 {
				host, portText = left[:idx], left[idx+1:]
			} else {
				continue
			}
		}
		host = strings.Trim(strings.TrimSpace(host), "[]")
		hostPort, err := strconv.Atoi(strings.TrimSpace(portText))
		if err != nil || hostPort < 1 || hostPort > 65535 {
			continue
		}
		public := host == "" || host == "0.0.0.0" || host == "::"
		out = append(out, ContainerPort{
			Runtime:       runtime,
			ContainerID:   row.ID,
			ContainerName: row.Names,
			Image:         row.Image,
			HostIP:        host,
			HostPort:      hostPort,
			ContainerPort: containerPort,
			Protocol:      proto,
			Public:        public,
		})
	}
	return out
}
