export type Process = { pid: number; name: string; executable?: string };
export type Port = {
  socketId: string;
  port: number;
  protocol: string;
  address: string;
  family: string;
  state: string;
  listening: boolean;
  loopback: boolean;
  processes: Process[];
};
export type ProcessGroup = { id: string; processes: Process[]; ports: Port[] };

// Summaries never include missing ports; every gap starts a separate interval.
export function summarizePorts(values: number[]) {
  const ports = [...new Set(values)].sort((a, b) => a - b);
  return {
    range: formatPortRanges(ports) || '—',
    count: ports.length,
    sparse:
      ports.length > 1 &&
      ports[ports.length - 1] - ports[0] + 1 !== ports.length,
  };
}

export function splitPortSegments<T>(
  items: T[],
  getPort: (item: T) => number,
): T[][] {
  const sorted = [...items].sort((a, b) => getPort(a) - getPort(b));
  const segments: T[][] = [];
  let last = -1;
  for (const item of sorted) {
    const port = getPort(item);
    if (!segments.length || port > last + 1) segments.push([]);
    segments[segments.length - 1].push(item);
    last = port;
  }
  return segments;
}

// Only consecutive, actually present ports become a range; gaps stay visible.
export function formatPortRanges(values: number[]): string {
  const ports = [...new Set(values)].sort((a, b) => a - b);
  const ranges: string[] = [];
  for (let i = 0; i < ports.length; i++) {
    const start = ports[i];
    let end = start;
    while (ports[i + 1] === end + 1) end = ports[++i];
    ranges.push(start === end ? String(start) : `${start}-${end}`);
  }
  return ranges.join(', ');
}

// Executable identity joins workers of one application, while different binaries
// and unidentified owners remain separate. Exact PIDs stay on socket details.
export function groupPortsByProcess(ports: Port[]): ProcessGroup[] {
  const groups = new Map<string, ProcessGroup>();
  for (const port of ports) {
    const owners = [
      ...new Map(port.processes.map((owner) => [owner.pid, owner])).values(),
    ].sort((a, b) => a.pid - b.pid);
    const identities = [
      ...new Set(
        owners.map((owner) =>
          owner.executable ? `exe:${owner.executable}` : `pid:${owner.pid}`,
        ),
      ),
    ].sort();
    const id = owners.length
      ? JSON.stringify(identities)
      : `socket:${port.family}:${port.protocol}:${port.socketId}`;
    const group = groups.get(id);
    if (group) {
      group.ports.push(port);
    } else
      groups.set(id, {
        id,
        processes: owners,
        ports: [port],
      });
  }
  return [...groups.values()].flatMap((group) =>
    splitPortSegments(group.ports, (port) => port.port).map((ports) => ({
      id: `${group.id}:${ports[0].port}`,
      processes: [
        ...new Map(
          ports
            .flatMap((port) => port.processes)
            .map((owner) => [owner.pid, owner]),
        ).values(),
      ].sort((a, b) => a.pid - b.pid),
      ports: ports.sort(
        (a, b) =>
          a.port - b.port ||
          a.protocol.localeCompare(b.protocol) ||
          a.address.localeCompare(b.address),
      ),
    })),
  );
}

export type RulePort = {
  port?: number;
  portRange?: string;
  protocol: string;
  source: string;
  label: string;
  owned: boolean;
  exists: boolean;
};
export function groupFirewallRules<T extends RulePort>(
  rules: T[],
  closedIds: Set<string>,
) {
  const groups = new Map<
    string,
    { id: string; rules: T[]; range: string; sparse: boolean }
  >();
  for (const rule of rules) {
    // Only automatic service rules with the same label, protocol and state join.
    // Manual, protected and already ranged rules retain their own identity.
    const id =
      rule.source === 'service' && rule.label && rule.port && !rule.portRange
        ? JSON.stringify([
            rule.source,
            [
              ...new Set(
                rule.label
                  .split(',')
                  .map((name) => name.trim())
                  .filter(Boolean),
              ),
            ].sort(),
            rule.protocol,
            rule.owned,
            rule.exists,
            closedIds.has(`close-port-${rule.port}-${rule.protocol}`),
          ])
        : JSON.stringify([
            rule.source,
            rule.portRange || rule.port,
            rule.protocol,
          ]);
    const group = groups.get(id);
    if (group) group.rules.push(rule);
    else groups.set(id, { id, rules: [rule], range: '', sparse: false });
  }
  return [...groups.values()].flatMap((group) =>
    splitPortSegments(group.rules, (rule) => rule.port || 0).map((rules) => {
      const summary = summarizePorts(
        rules.flatMap((rule) => (rule.port ? [rule.port] : [])),
      );
      return {
        id: `${group.id}:${rules[0].portRange || rules[0].port}`,
        rules,
        range: rules[0].portRange || summary.range,
        sparse: summary.sparse,
      };
    }),
  );
}
