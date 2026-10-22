import assert from 'node:assert/strict';
import test from 'node:test';
import {
  accessStateLabel,
  socketStateLabel,
  firewallSourceLabel,
  firewallActionLabel,
  diagnosisVerdictLabel,
  diagnosticText,
} from '../src/pages/firewall/uiLabels.ts';

test('all port-access states are consistently Russian and English', () => {
  const cases = [
    ['open', 'ОТКРЫТ', 'OPEN'],
    ['closed', 'ЗАКРЫТ', 'CLOSED'],
    ['pending-close', 'НЕ ЗАКРЫТ', 'NOT CLOSED'],
    ['unfiltered', 'НЕ ФИЛЬТРУЕТСЯ', 'UNFILTERED'],
    ['unknown', 'НЕ ОПРЕДЕЛЕНО', 'UNKNOWN'],
  ];
  for (const [state, ru, en] of cases) {
    assert.equal(accessStateLabel(state, true), ru);
    assert.equal(accessStateLabel(state, false), en);
  }
});

test('socket state is not confused with host firewall permission', () => {
  assert.equal(socketStateLabel('LISTEN', true), 'СЛУШАЕТ');
  assert.equal(socketStateLabel('ESTABLISHED', true), 'СОЕДИНЕНИЕ УСТАНОВЛЕНО');
  assert.equal(socketStateLabel('CLOSED', true), 'ЗАКРЫТО');
  assert.equal(socketStateLabel('LISTEN', false), 'LISTEN');
  assert.equal(socketStateLabel('CUSTOM_KERNEL_STATE', true), 'CUSTOM_KERNEL_STATE');
});

test('rule source captions translate only known service defaults, not user names', () => {
  assert.equal(firewallSourceLabel('external', 'Host firewall', true), 'Системный файрволл');
  assert.equal(firewallSourceLabel('external', undefined, true), 'Внешнее правило файрволла');
  assert.equal(firewallSourceLabel('service', undefined, true), 'Сервис (автоматически)');
  assert.equal(firewallSourceLabel('manual', 'Manual rule', true), 'Ручное правило');
  assert.equal(firewallSourceLabel('panel', 'Web panel', true), 'Веб-панель');
  assert.equal(firewallSourceLabel('service', 'my-process', true), 'my-process');
  assert.equal(firewallSourceLabel('manual', 'Моё название', true), 'Моё название');
  assert.equal(firewallSourceLabel('external', 'Host firewall', false), 'Host firewall');
});

test('advanced rule actions and access diagnostics are localized', () => {
  assert.equal(firewallActionLabel('allow', true), 'РАЗРЕШИТЬ');
  assert.equal(firewallActionLabel('deny', true), 'ЗАПРЕТИТЬ');
  assert.equal(firewallActionLabel('allow', false), 'ALLOW');
  assert.equal(diagnosisVerdictLabel('predicted-allow', true), 'ВЕРОЯТНО РАЗРЕШЕНО');
  assert.equal(diagnosisVerdictLabel('predicted-deny', true), 'ВЕРОЯТНО ЗАПРЕЩЕНО');
  assert.equal(diagnosisVerdictLabel('unknown', true), 'НЕ ОПРЕДЕЛЕНО');
  assert.equal(diagnosticText('Matches managed advanced allow rule', true), 'Подходит под управляемое расширенное разрешающее правило.');
  assert.match(diagnosticText('Deny rule overlaps an active allow rule', true), /^Запрещающее правило/);
  assert.equal(diagnosticText('unexpected administrator message', true), 'unexpected administrator message');
  assert.equal(diagnosticText('Deny rule overlaps an active allow rule', false), 'Deny rule overlaps an active allow rule');
});
