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

export function groupPortsByProcess(ports: Port[]): ProcessGroup[] {
  const groups = new Map<string, ProcessGroup>();
  for (const port of ports) {
    const owners = [...new Map(port.processes.map((owner) => [owner.pid, owner])).values()].sort((a, b) => a.pid - b.pid);
    // Shared sockets have their own owner-set group. Unknown owners must never
    // be combined into an imaginary process, even in diagnostic mode.
    const id = owners.length ? `process:${owners.map((owner) => owner.pid).join(',')}` : `socket:${port.family}:${port.protocol}:${port.socketId}`;
    const group = groups.get(id);
    if (group) group.ports.push(port);
    else groups.set(id, { id, processes: owners, ports: [port] });
  }
  return [...groups.values()].map((group) => ({ ...group, ports: group.ports.sort((a, b) => a.port - b.port || a.protocol.localeCompare(b.protocol) || a.address.localeCompare(b.address)) }));
}
