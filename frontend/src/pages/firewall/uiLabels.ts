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
  'Listening port': 'Слушающий порт',
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

/** Known human-readable messages emitted by the service, preserved in English for API clients. */
const russianDiagnosticMessages: Record<string, string> = {
  'Saved close has no verified live kernel enforcement':
    'Запрет сохранён, но его применение в ядре не подтверждено.',
  'Verified explicit INPUT and DNAT/FORWARD port close':
    'Закрытие порта подтверждено правилами INPUT и DNAT/FORWARD.',
  'Owned nftables INPUT hook is missing or changed':
    'Входящая цепочка nftables панели отсутствует или изменена.',
  'Container FORWARD hook is missing or changed':
    'Цепочка FORWARD для защиты контейнеров отсутствует или изменена.',
  'UFW insertion order, not the displayed numeric priority, determines effective precedence.':
    'В UFW порядок применения определяется порядком добавления правил, а не отображаемым числовым приоритетом.',
  'Effective results depend on active zone bindings and existing administrator rules.':
    'Результат зависит от активных зон и уже существующих правил администратора.',
  'Overlapping advanced rules; verify effective order':
    'Расширенные правила пересекаются. Проверьте порядок применения.',
  'Overlapping allow/deny rules may produce unexpected access':
    'Пересекающиеся разрешающие и запрещающие правила могут привести к неожиданному доступу.',
  'Deny rule overlaps an active allow rule':
    'Запрещающее правило пересекается с действующим разрешающим правилом.',
  'Local rule prediction only; external security groups, routing, other nftables/iptables rules and service-level access controls are not verified.':
    'Это лишь оценка локальных правил. Внешние группы безопасности, маршрутизация, другие правила nftables/iptables и ограничения самих сервисов не проверены.',
  'Container traffic is forwarded after DNAT; the dedicated FORWARD policy must be considered.':
    'Трафик контейнеров перенаправляется после DNAT. Необходимо учитывать отдельную политику FORWARD.',
  'Container FORWARD protection is disabled; INPUT allows/denies do not reliably protect published ports.':
    'Защита контейнеров в FORWARD отключена. Правила INPUT не гарантируют защиту опубликованных портов.',
  'No matching listening service or published container was detected':
    'Не обнаружен соответствующий слушающий сервис или опубликованный контейнер.',
  "A container's allow exception must be present in the FORWARD policy as well":
    'Разрешающее исключение для контейнера должно также присутствовать в правилах FORWARD.',
  'Container published port; inspect FORWARD/DOCKER-USER rules':
    'Порт опубликован контейнером: проверьте правила FORWARD/DOCKER-USER.',
  'Firewall-UI management is disabled':
    'Управление файрволлом через Firewall-UI выключено.',
  'Protected panel or SSH rule precedes advanced rules':
    'Защитное правило панели или SSH применяется раньше расширенных правил.',
  'Explicit container FORWARD exception':
    'Явное разрешающее исключение для контейнера в FORWARD.',
  'Container FORWARD default-deny rule matches this published port':
    'На опубликованный порт распространяется правило запрета FORWARD по умолчанию.',
  'Matches a managed port allow rule':
    'Подходит под управляемое разрешающее правило порта.',
  'No matching managed allow rule; other backend rules may still affect access':
    'Подходящее управляемое разрешающее правило не найдено. Другие системные правила всё ещё могут влиять на доступ.',
  'nftables is required for forwarded container traffic protection':
    'Для защиты перенаправленного трафика контейнеров требуется nftables.',
  'Counters are kernel totals since the last rule installation; replacing nftables rules resets them. External firewall rules are not counted.':
    'Счётчики отражают трафик ядра с момента последней установки правил. При замене правил nftables они обнуляются. Внешние правила не учитываются.',
  'Per-rule counters are not available for the current backend. No traffic statistics are invented.':
    'Счётчики отдельных правил недоступны для текущего файрволла. Статистика трафика не подменяется приблизительными значениями.',
};

export function diagnosticText(value: string | undefined, ru: boolean): string {
  if (!value) return '';
  if (!ru) return value;
  if (value.startsWith('Matches managed advanced ') && value.endsWith(' rule')) {
    const action = value.slice('Matches managed advanced '.length, -' rule'.length);
    if (action === 'allow') return 'Подходит под управляемое расширенное разрешающее правило.';
    if (action === 'deny') return 'Подходит под управляемое расширенное запрещающее правило.';
  }
  return russianDiagnosticMessages[value] || value;
}
