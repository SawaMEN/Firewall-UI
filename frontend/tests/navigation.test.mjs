import assert from 'node:assert/strict';
import test from 'node:test';
import { getPageFromHash } from '../src/pages/firewall/navigation.ts';

test('navigation restores selected tab from the URL after reload', () => {
  for (const page of ['overview', 'firewall', 'ports', 'settings']) {
    assert.equal(getPageFromHash('#' + page), page);
  }
  assert.equal(getPageFromHash('#/firewall'), 'firewall');
});

test('invalid navigation hashes cannot select unknown pages', () => {
  for (const hash of ['', '#', '#unknown', '#/settings/other', '#<script>']) {
    assert.equal(getPageFromHash(hash), 'overview');
  }
});
