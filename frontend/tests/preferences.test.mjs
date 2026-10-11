import assert from 'node:assert/strict';
import test from 'node:test';
import { savedLanguage, saveLanguage } from '../src/preferences.ts';
test('blocked storage preserves login defaults and permits language selection', () => {
  globalThis.localStorage = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };
  assert.equal(savedLanguage(), 'ru');
  assert.doesNotThrow(() => saveLanguage('en'));
  globalThis.localStorage = { getItem: () => 'en', setItem() {} };
  assert.equal(savedLanguage(), 'en');
  globalThis.localStorage.getItem = () => 'unknown';
  assert.equal(savedLanguage(), 'ru');
  delete globalThis.localStorage;
});
