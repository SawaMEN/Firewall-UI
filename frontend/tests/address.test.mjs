import assert from 'node:assert/strict';
import test from 'node:test';
import { describeAddress, socketEndpoint } from '../src/pages/firewall/address.ts';
test('wildcard and loopback addresses explain their scope and keep exact endpoints', () => {
  assert.equal(describeAddress('0.0.0.0', 'IPv4').label, 'Все интерфейсы');
  assert.equal(describeAddress('::', 'IPv6').family, 'IPv6');
  for (const address of ['127.0.0.1', '127.0.1.1', '::1', '::ffff:127.0.0.1']) assert.equal(describeAddress(address, '').label, 'Только этот сервер');
  assert.equal(describeAddress('192.168.1.5', 'IPv4').label, '192.168.1.5');
  assert.equal(socketEndpoint('::', 443), '[::]:443');
  assert.equal(socketEndpoint('2001:db8::1', 443), '[2001:db8::1]:443');
  assert.equal(socketEndpoint('0.0.0.0', 443), '0.0.0.0:443');
});
