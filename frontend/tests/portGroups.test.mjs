import assert from 'node:assert/strict';
import test from 'node:test';
import { formatPortRanges, groupPortsByProcess, summarizePorts } from '../src/pages/firewall/portGroups.ts';

const socket = (port, processes, extra = {}) => ({ socketId: String(port), port, processes, protocol: 'tcp', address: '0.0.0.0', family: 'IPv4', state: 'LISTEN', listening: true, loopback: false, ...extra });
test('ranges use hyphens and never fill gaps or duplicate ports', () => {
  assert.equal(formatPortRanges([9005, 9004, 9003, 8080, 8002, 8000, 8001, 8001]), '8000-8002, 8080, 9003-9005');
  assert.equal(formatPortRanges([65535, 65534, 1]), '1, 65534-65535');
  assert.equal(formatPortRanges([]), '');
});
test('one process group contains TCP, UDP and multiple addresses', () => {
  const owner = { pid: 100, name: 'xray' };
  const groups = groupPortsByProcess([socket(9000, [owner]), socket(9001, [owner], { protocol: 'udp' }), socket(9000, [owner], { family: 'IPv6', address: '::' })]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].ports.length, 3);
});
test('same process names do not combine separate PIDs, shared owners use exact sets', () => {
  const a = { pid: 100, name: 'worker' }, b = { pid: 101, name: 'worker' };
  const groups = groupPortsByProcess([socket(80, [a]), socket(81, [b]), socket(82, [a, b]), socket(83, [b, a])]);
  assert.equal(groups.length, 3);
  assert.equal(groups.find((group) => group.processes.length === 2).ports.length, 2);
});
test('ownerless diagnostic sockets stay separate', () => {
  assert.equal(groupPortsByProcess([socket(9000, []), socket(9001, [])]).length, 2);
});

test('process extent uses a hyphen across sparse and mixed-protocol ports without filling gaps', () => {
  assert.deepEqual(summarizePorts([8443, 443, 8443]), { range: '443-8443', count: 2, sparse: true });
  assert.deepEqual(summarizePorts([9001, 9000]), { range: '9000-9001', count: 2, sparse: false });
  assert.deepEqual(summarizePorts([443, 443]), { range: '443', count: 1, sparse: false });
  assert.deepEqual(summarizePorts([]), { range: '—', count: 0, sparse: false });
});
