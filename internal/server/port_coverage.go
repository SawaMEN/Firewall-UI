package server

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/SawaMEN/Firewall-UI/internal/service"
)

type portInterval struct {
	start int
	end   int
}

// Match only observed sockets. Expanding rule ranges wastes memory and used to
// truncate coverage after 2048 ports, incorrectly flagging the remaining ports.
func coveredListeningPorts(ports []service.Port, enabled bool, basic []service.FirewallRule, advanced []service.FirewallAdvancedRule) map[string]bool {
	covered := make(map[string]bool)
	if !enabled {
		return covered
	}
	intervals := make(map[string][]portInterval)
	add := func(protocol string, start, end int) {
		if start < 1 || end < start || end > 65535 {
			return
		}
		protocols := []string{protocol}
		if protocol == "any" || protocol == "both" {
			protocols = []string{"tcp", "udp"}
		}
		for _, name := range protocols {
			intervals[name] = append(intervals[name], portInterval{start, end})
		}
	}
	for _, rule := range basic {
		if !rule.Exists {
			continue
		}
		start, end := rule.Port, rule.Port
		if rule.PortRange != "" {
			left, right, ranged := strings.Cut(strings.ReplaceAll(rule.PortRange, ":", "-"), "-")
			start, _ = strconv.Atoi(left)
			end = start
			if ranged {
				end, _ = strconv.Atoi(right)
			}
		}
		add(rule.Protocol, start, end)
	}
	for _, rule := range advanced {
		if rule.Action != "allow" {
			continue
		}
		start, end := rule.PortStart, rule.PortEnd
		if start == 0 {
			start, end = 1, 65535
		} else if end == 0 {
			end = start
		}
		add(rule.Protocol, start, end)
	}
	for protocol, ranges := range intervals {
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
		merged := ranges[:0]
		for _, interval := range ranges {
			last := len(merged) - 1
			if last >= 0 && interval.start <= merged[last].end+1 {
				merged[last].end = max(merged[last].end, interval.end)
			} else {
				merged = append(merged, interval)
			}
		}
		intervals[protocol] = merged
	}
	for _, port := range ports {
		if !port.Listening {
			continue
		}
		ranges := intervals[port.Protocol]
		index := sort.Search(len(ranges), func(i int) bool { return ranges[i].end >= port.Port })
		if index < len(ranges) && ranges[index].start <= port.Port {
			covered[fmt.Sprintf("%d/%s", port.Port, port.Protocol)] = true
		}
	}
	return covered
}
