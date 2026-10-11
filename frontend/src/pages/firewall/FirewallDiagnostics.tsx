import { useEffect, useState } from 'react';
import { Alert, Button, Card, Divider, Input, InputNumber, Select, Space, Switch, Table, Tag, Typography } from 'antd';
import { HttpUtil } from '@/utils';

type Zone = { name: string; interfaces: string[]; active: boolean };
type Zones = { supported: boolean; selected: string; default: string; zones: Zone[] };
type Containers = { enabled: boolean; supported: boolean; active: boolean; ports: { containerName: string; hostPort: number; protocol: string; public: boolean }[]; message?: string };
type Conflict = { first: string; second: string; severity: string; message: string };
type Analysis = { backend: string; conflicts: Conflict[]; notes: string[] };
type Diagnosis = { verdict: string; rule?: string; reason: string; backend: string; listener: boolean; processes: { pid: number; name: string }[]; containers: { containerName: string; hostPort: number }[]; notes: string[] };
type Counter = { rule: string; packets: number; bytes: number; table: string };
type Traffic = { supported: boolean; counters: Counter[]; note: string };

export default function FirewallDiagnostics({ backend, enabled, ru, onReload }: { backend: string; enabled: boolean; ru: boolean; onReload: () => void }) {
  const [zones, setZones] = useState<Zones | null>(null);
  const [containers, setContainers] = useState<Containers | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [traffic, setTraffic] = useState<Traffic | null>(null);
  const [history, setHistory] = useState<number[]>([]);
  const [zone, setZone] = useState('');
  const [busy, setBusy] = useState('');
  const [sourceIp, setSourceIp] = useState('203.0.113.10');
  const [port, setPort] = useState<number | null>(443);
  const [protocol, setProtocol] = useState('tcp');
  const [iface, setIface] = useState('');
  const [diagnosis, setDiagnosis] = useState<Diagnosis | null>(null);
  const [error, setError] = useState('');

  async function refresh() {
    const [rules, docker, counts] = await Promise.all([
      HttpUtil.get<Analysis>('/api/firewall/analyze'),
      HttpUtil.get<Containers>('/api/firewall/containers'),
      HttpUtil.get<Traffic>('/api/firewall/traffic'),
    ]);
    if (rules.success && rules.obj) setAnalysis(rules.obj);
    if (docker.success && docker.obj) setContainers(docker.obj);
    if (counts.success && counts.obj) {
      setTraffic(counts.obj);
      // Display sampled cumulative totals; a reset occurs when a rule is replaced.
      setHistory((old) => [...old, counts.obj!.counters.reduce((sum, item) => sum + item.packets, 0)].slice(-20));
    }
    if (backend === 'firewalld') {
      const res = await HttpUtil.get<Zones>('/api/firewall/zones');
      if (res.success && res.obj) { setZones(res.obj); setZone(res.obj.selected); }
    }
  }
  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => {
      if (!document.hidden) void refresh();
    }, 15000);
    return () => window.clearInterval(timer);
  }, [backend]);

  async function selectZone() {
    setBusy('zone'); setError('');
    try {
      const res = await HttpUtil.post<{ zones: Zones }>('/api/firewall/zones', { zone });
      if (res.success && res.obj) { setZones(res.obj.zones); onReload(); }
      else setError(res.msg);
    } finally { setBusy(''); }
  }
  async function setProtection(value: boolean) {
    setBusy('docker'); setError('');
    try {
      const res = await HttpUtil.post<{ status: Containers }>('/api/firewall/containers', { enabled: value });
      if (res.success && res.obj) { setContainers(res.obj.status); onReload(); }
      else setError(res.msg);
    } finally { setBusy(''); }
  }
  async function inspect() {
    if (!port) return;
    setBusy('check'); setError('');
    try {
      const res = await HttpUtil.post<Diagnosis>('/api/firewall/inspect', { sourceIp, port, protocol, interface: iface });
      if (res.success && res.obj) setDiagnosis(res.obj);
      else setError(res.msg);
    } finally { setBusy(''); }
  }

  const min = Math.min(...history, 0);
  const max = Math.max(...history, 1);
  const points = history.map((n, i) => {
    const x = history.length === 1 ? 0 : i * 100 / (history.length - 1);
    const y = 35 - (n - min) * 30 / (max - min || 1);
    return `${x},${y}`;
  }).join(' ');

  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      {error && <Alert type="error" title={error} showIcon closable onClose={() => setError('')} />}
      {backend === 'firewalld' && zones?.supported && (
        <Card className="panel-card" title={ru ? 'Зоны firewalld' : 'Firewalld zones'}>
          <Space wrap>
            <Select value={zone} onChange={setZone} style={{ minWidth: 180 }}
              disabled={enabled} options={zones.zones.map((item) => ({
                value: item.name, label: `${item.name}${item.active ? ' (active)' : ''}`,
              }))} />
            <Button loading={busy === 'zone'} disabled={enabled || zone === zones.selected}
              onClick={() => void selectZone()}>{ru ? 'Выбрать зону' : 'Select zone'}</Button>
          </Space>
          <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>
            {ru ? 'Сменить зону можно после отключения управления файрволлом в панели. Системный firewalld продолжает работать.' :
              'Disable panel firewall management before changing zones. The system firewalld service remains running.'}
          </Typography.Paragraph>
          {zones.zones.filter((item) => item.active).map((item) => (
            <div key={item.name}><Tag>{item.name}</Tag>{item.interfaces.join(', ') || (ru ? 'Без привязанных интерфейсов' : 'No interfaces assigned')}</div>
          ))}
        </Card>
      )}

      <Card className="panel-card" title={ru ? 'Опубликованные порты Docker/Podman' : 'Docker/Podman published ports'}>
        <Space align="center" wrap>
          <Switch checked={!!containers?.enabled} disabled={!containers?.supported || !enabled}
            loading={busy === 'docker'} onChange={(value) => void setProtection(value)} />
          <Typography.Text>{ru ? 'Фильтровать DNAT в цепочке FORWARD' : 'Filter DNAT traffic in FORWARD'}</Typography.Text>
          <Tag>{containers?.active ? (ru ? 'Активно' : 'Active') : (ru ? 'Неактивно' : 'Inactive')}</Tag>
        </Space>
        <Typography.Paragraph type="secondary" style={{ marginTop: 10 }}>
          {containers?.message || (ru
            ? 'По умолчанию опубликованные порты блокируются; разрешения задаются ручными или расширенными правилами. Применяется отдельная nftables-таблица, цепочки Docker не меняются.'
            : 'Published ports default to blocked; exceptions follow manual/advanced rules. A separate nftables table is used; Docker chains are not modified.')}
        </Typography.Paragraph>
        <Typography.Text type="secondary">{ru ? 'Обнаружено опубликованных портов' : 'Published port mappings'}: {containers?.ports.filter((p) => p.public).length ?? '—'}</Typography.Text>
      </Card>

      <Card className="panel-card" title={ru ? 'Анализ конфликтующих правил' : 'Rule conflict analysis'}
        extra={<Button size="small" onClick={() => void refresh()}>{ru ? 'Обновить' : 'Refresh'}</Button>}>
        {analysis?.notes.map((note) => <Alert key={note} type="info" title={note} style={{ marginBottom: 8 }} />)}
        {analysis?.conflicts.length === 0 ? <Typography.Text type="secondary">{ru ? 'Очевидных пересечений не обнаружено' : 'No obvious overlaps detected'}</Typography.Text> : (
          <Table<Conflict> size="small" rowKey={(x) => `${x.first}/${x.second}`}
            dataSource={analysis?.conflicts || []} pagination={{ pageSize: 8 }}
            columns={[
              { title: ru ? 'Правило 1' : 'Rule 1', dataIndex: 'first' },
              { title: ru ? 'Правило 2' : 'Rule 2', dataIndex: 'second' },
              { title: ru ? 'Проблема' : 'Issue', render: (_, row) => <Tag color={row.severity === 'danger' ? 'error' : 'warning'}>{row.message}</Tag> },
            ]}
          />
        )}
      </Card>

      <Card className="panel-card" title={ru ? 'Проверка доступа и диагностика подключения' : 'Access check and connection diagnostics'}>
        <Space wrap>
          <Input value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} placeholder={ru ? 'IP источника' : 'Source IP'} style={{ width: 170 }} />
          <InputNumber min={1} max={65535} value={port} onChange={setPort} placeholder={ru ? 'Порт' : 'Port'} />
          <Select value={protocol} onChange={setProtocol} style={{ width: 95 }}
            options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]} />
          <Input value={iface} onChange={(e) => setIface(e.target.value)} placeholder={ru ? 'Интерфейс (опц.)' : 'Interface (opt.)'} style={{ width: 155 }} />
          <Button type="primary" loading={busy === 'check'} onClick={() => void inspect()}>{ru ? 'Проверить' : 'Check'}</Button>
        </Space>
        {diagnosis && <>
          <Divider />
          <Space wrap>
            <Tag color={diagnosis.verdict === 'predicted-deny' ? 'error' : diagnosis.verdict === 'predicted-allow' ? 'success' : 'warning'}>{diagnosis.verdict}</Tag>
            <Typography.Text>{diagnosis.reason}</Typography.Text>
          </Space>
          <Typography.Paragraph style={{ marginTop: 8 }}>
            {ru ? 'Локальный слушающий сокет' : 'Local listening socket'}: {diagnosis.listener ? (ru ? 'есть' : 'yes') : (ru ? 'не найден' : 'not detected')}.
            {' '}{ru ? 'Процессы' : 'Processes'}: {diagnosis.processes.map((p) => `${p.name} (${p.pid})`).join(', ') || '—'}.
            {' '}{ru ? 'Контейнеры' : 'Containers'}: {diagnosis.containers.map((p) => p.containerName).join(', ') || '—'}.
          </Typography.Paragraph>
          {diagnosis.notes.map((note) => <Typography.Paragraph type="secondary" key={note}>{note}</Typography.Paragraph>)}
        </>}
      </Card>

      <Card className="panel-card" title={ru ? 'Счётчики сетевого трафика' : 'Traffic counters'}>
        <Typography.Paragraph type="secondary">{traffic?.note}</Typography.Paragraph>
        {traffic?.supported && <>
          <Typography.Text type="secondary">{ru ? 'Динамика суммарных пакетов (последние опросы)' : 'Sampled total packet counts'}</Typography.Text>
          <svg viewBox="0 0 100 40" width="100%" height="95" preserveAspectRatio="none" role="img" aria-label="Packet counter history">
            <polyline points={points} fill="none" stroke="currentColor" strokeWidth="0.8" />
          </svg>
          <Table<Counter> size="small" rowKey={(row, i) => `${row.table}:${row.rule}:${i}`} dataSource={traffic.counters} pagination={{ pageSize: 10 }}
            columns={[
              { title: ru ? 'Правило' : 'Rule', dataIndex: 'rule', ellipsis: true },
              { title: ru ? 'Пакеты' : 'Packets', dataIndex: 'packets', render: (n: number) => n.toLocaleString() },
              { title: ru ? 'Байты' : 'Bytes', dataIndex: 'bytes', render: (n: number) => n.toLocaleString() },
            ]}
          />
        </>}
      </Card>
    </Space>
  );
}
