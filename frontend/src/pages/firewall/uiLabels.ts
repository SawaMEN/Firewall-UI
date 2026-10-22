/** Display-only translations. Never use these values in firewall API requests. */
export type AccessState = 'unfiltered' | 'closed' | 'pending-close' | 'open' | 'unknown';

export function accessStateLabel(state: AccessState, ru: boolean): string {
  const labels: Record<AccessState, [string, string]> = {
    unfiltered: ['НЕ ФИЛЬТРУЕТСЯ', 'UNFILTERED'],
    closed: ['ЗАКРЫТ', 'CLOSED'],
    'pending-close': ['НЕ ЗАКРЫТ', 'NOT CLOSED'],
    open: ['ОТКРЫТ', 'OPEN'],
    unknown: ['НЕ ОПРЕДЕЛЕНО', 'UNKNOWN'],
  };
  return labels[state][ru ? 0 : 1];
}

const russianSocketStates: Record<string, string> = {
  LISTEN: 'СЛУШАЕТ',
  LISTENING: 'СЛУШАЕТ',
  ESTABLISHED: 'СОЕДИНЕНИЕ УСТАНОВЛЕНО',
  SYN_SENT: 'ОТПРАВЛЕН SYN',
  SYN_RECV: 'ПОЛУЧЕН SYN',
  SYN_RECEIVED: 'ПОЛУЧЕН SYN',
  FIN_WAIT1: 'ОЖИДАНИЕ ЗАКРЫТИЯ 1',
  FIN_WAIT2: 'ОЖИДАНИЕ ЗАКРЫТИЯ 2',
  TIME_WAIT: 'ОЖИДАНИЕ ЗАВЕРШЕНИЯ',
  CLOSE_WAIT: 'ОЖИДАНИЕ ЗАКРЫТИЯ',
  LAST_ACK: 'ПОСЛЕДНЕЕ ПОДТВЕРЖДЕНИЕ',
  CLOSING: 'ЗАКРЫВАЕТСЯ',
  CLOSED: 'ЗАКРЫТО',
  CLOSE: 'ЗАКРЫТО',
  UNCONN: 'БЕЗ СОЕДИНЕНИЯ',
  UNKNOWN: 'НЕИЗВЕСТНО',
};

export function socketStateLabel(state: string, ru: boolean): string {
  if (!ru || !state) return state;
  return russianSocketStates[state.toUpperCase()] ?? state;
}

const russianRuleLabels: Record<string, string> = {
  'Web panel': 'Веб-панель',
  'Configured reverse proxy port': 'Настроенный порт обратного прокси',
  'Current panel connection': 'Текущее подключение к панели',
  'Manual rule': 'Ручное правило',
  'Host firewall': 'Системный файрволл',
};

export function firewallSourceLabel(source: string, label: string | undefined, ru: boolean): string {
  if (label?.trim()) return ru ? (russianRuleLabels[label] || label) : label;
  const names: Record<string, [string, string]> = {
    closed: ['Закрыт вручную', 'Closed manually'],
    external: ['Внешнее правило файрволла', 'External firewall rule'],
    service: ['Сервис (автоматически)', 'Service (automatic)'],
    manual: ['Ручное правило', 'Manual rule'],
    panel: ['Веб-панель', 'Web panel'],
    session: ['Подключение к панели', 'Panel connection'],
    ssh: ['SSH', 'SSH'],
  };
  return names[source]?.[ru ? 0 : 1] || source;
}

export function firewallActionLabel(action: string, ru: boolean): string {
  if (!ru) return action.toUpperCase();
  switch (action.toLowerCase()) {
    case 'allow': return 'РАЗРЕШИТЬ';
    case 'deny': return 'ЗАПРЕТИТЬ';
    case 'reject': return 'ОТКЛОНИТЬ';
    default: return action.toUpperCase();
  }
}

export function diagnosisVerdictLabel(verdict: string, ru: boolean): string {
  if (!ru) return verdict;
  switch (verdict) {
    case 'predicted-allow': return 'ВЕРОЯТНО РАЗРЕШЕНО';
    case 'predicted-deny': return 'ВЕРОЯТНО ЗАПРЕЩЕНО';
    case 'unknown': return 'НЕ ОПРЕДЕЛЕНО';
    default: return verdict;
  }
}
