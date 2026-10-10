import assert from 'node:assert/strict';
import test from 'node:test';
import { pairProtocolRules, formatProtocols, formatPortRanges, groupPortsByProcess, groupFirewallRules, summarizePorts } from '../src/pages/firewall/portGroups.ts';

const socket = (port, processes, extra = {}) => ({ socketId: String(port), port, processes, protocol: 'tcp', address: '0.0.0.0', family: 'IPv4', state: 'LISTEN', listening: true, loopback: false, ...extra });
test('ranges use hyphens and never fill gaps or duplicate ports', () => {
  assert.equal(formatPortRanges([9005, 9004, 9003, 8080, 8002, 8000, 8001, 8001]), '8000-8002, 8080, 9003-9005');
  assert.equal(formatPortRanges([65535, 65534, 1]), '1, 65534-65535');
  assert.equal(formatPortRanges([]), '');
});
test('one process group contains TCP, UDP and multiple addresses', () => {
  const owner = { pid: 100, name: 'worker' };
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

test('summaries split gaps and use hyphens only for consecutive occupied ports', () => {
  assert.deepEqual(summarizePorts([8443, 443, 8443]), { range: '443, 8443', count: 2, sparse: true });
  assert.deepEqual(summarizePorts([9001, 9000]), { range: '9000-9001', count: 2, sparse: false });
  assert.deepEqual(summarizePorts([443, 443]), { range: '443', count: 1, sparse: false });
  assert.deepEqual(summarizePorts([]), { range: '—', count: 0, sparse: false });
});

test('workers of the same executable show one range and retain every PID', () => {
  const a = { pid: 100, name: 'proxy', executable: '/usr/bin/proxy' };
  const b = { ...a, pid: 101 };
  const groups = groupPortsByProcess([socket(9000, [a]), socket(9002, [b]), socket(9001, [a, b]), socket(9100, [{ ...a, pid: 102, executable: '/other/proxy' }])]);
  assert.equal(groups.length, 2);
  assert.equal(summarizePorts(groups[0].ports.map(p => p.port)).range, '9000-9002');
  assert.deepEqual(groups[0].processes.map(p => p.pid), [100, 101]);
});
test('firewall ranges preserve protection, gaps, protocol and denied state', () => {
  const rule = (port, extra = {}) => ({ port, source: 'service', label: 'worker', protocol: 'tcp', exists: true, owned: true, ...extra });
  const groups = groupFirewallRules([rule(9000), rule(9002), rule(9003), rule(9001), rule(22, { source: 'ssh' }), rule(9000, { protocol: 'udp' }), rule(9100, { source: 'manual' })], new Set(['close-port-9001-tcp']));
  assert.equal(groups.length, 5);
  assert.equal(groups[0].range, '9000');
  assert.equal(groups[1].range, '9002-9003');
  assert.equal(groups[0].sparse, false);
  assert.deepEqual(groups[1].rules.map(r => r.port), [9002, 9003]);
  assert.equal(groups[2].range, '9001');
});

test('large process gaps create separate rows while mixed sockets share a contiguous range', () => {
  const owner = { pid: 100, name: 'worker', executable: '/usr/bin/worker' };
  const groups = groupPortsByProcess([socket(443, [owner]), socket(8443, [owner]), socket(9000, [owner]), socket(9001, [{ ...owner, pid: 101 }]), socket(9002, [owner]), socket(9000, [owner], { protocol: 'udp' })]);
  assert.deepEqual(groups.map(group => summarizePorts(group.ports.map(port => port.port)).range), ['443', '8443', '9000-9002']);
  assert.deepEqual(groups[2].processes.map(owner => owner.pid), [100, 101]);
  assert.equal(groups[2].ports.length, 4);
});

test('combined protocols use a stable compact label', () => {
  assert.equal(formatProtocols(['UDP', 'tcp', 'TCP']), 'TCP + UDP');
  assert.equal(formatProtocols(['both', 'udp']), 'TCP + UDP');
  assert.equal(formatProtocols(['tcp']), 'TCP');
});

test('paired firewall ranges retain every original rule and never extend UDP coverage', () => {
  const rule = (port, protocol, extra = {}) => ({ port, protocol, source: 'service', label: 'worker', owned: true, exists: true, ...extra });
  const rules = [rule(9000, 'tcp'), rule(9001, 'tcp'), rule(9000, 'udp'), rule(9001, 'udp')];
  const paired = groupFirewallRules(rules, new Set());
  assert.equal(paired.length, 1);
  assert.equal(paired[0].range, '9000-9001');
  assert.deepEqual(new Set(paired[0].rules), new Set(rules));
  assert.equal(formatProtocols(paired[0].rules.map(rule => rule.protocol), ' / '), 'TCP / UDP');
  assert.equal(groupFirewallRules(rules.slice(0, 3), new Set()).length, 2);
  assert.equal(groupFirewallRules(rules, new Set(['close-port-9001-udp'])).length, 3);
});

test('manual and advanced pairing preserves semantics and individual deletion identities', () => {
  const a = { id: 'tcp-rule', protocol: 'tcp', action: 'allow', port: 443, source: '10.0.0.0/8' };
  const b = { ...a, id: 'udp-rule', protocol: 'udp' };
  const key = ({ action, port, source }) => JSON.stringify([action, port, source]);
  const groups = pairProtocolRules([a, b, { ...a, id: 'duplicate' }, { ...b, id: 'denied', action: 'deny' }, { ...b, id: 'different-source', source: 'ANY' }, { ...a, id: 'any-rule', protocol: 'any' }], key);
  assert.equal(groups.length, 5);
  assert.deepEqual(groups[0].rules.map(rule => rule.id), ['tcp-rule', 'udp-rule']);
  assert.equal(groups[0].rules[0], a);
  assert.equal(groups[0].rules[1], b);
});
