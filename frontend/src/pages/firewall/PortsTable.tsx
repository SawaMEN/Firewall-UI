import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Grid, Input, Popconfirm, Select, Space, Switch, Table, Tag, Typography } from 'antd';
import { PlusOutlined, ReloadOutlined, StopOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { HttpUtil } from '@/utils';

import type { ColumnsType } from 'antd/es/table';
import { formatPortRanges, groupPortsByProcess, type Port, type ProcessGroup } from './portGroups';

type ContainerPort = {
  runtime: string;
  containerId: string;
  containerName: string;
  image: string;
  hostIp: string;
  hostPort: number;
  containerPort: number;
  protocol: string;
  public: boolean;
};
type Snapshot = { ports: Port[]; containers: ContainerPort[]; updatedAt: string };
type FirewallRule = {
  port?: number;
  protocol: string;
  source: string;
  exists: boolean;
  owned: boolean;
};
type AdvancedRule = { id: string; action: string; portStart?: number; portEnd?: number; protocol: string };
type ManualRule = { port: number; protocol: string; label?: string };
type FirewallStatus = {
  enabled: boolean;
  autoSync: boolean;
  rules: FirewallRule[];
  manualRules: ManualRule[];
};

const key = (port: number, protocol: string) => `${port}/${protocol}`;

export function PortsTable() {
  const screens = Grid.useBreakpoint();
  const { i18n } = useTranslation();
  const ru = i18n.language.startsWith('ru');
  const [snapshot, setSnapshot] = useState<Snapshot>({ ports: [], containers: [], updatedAt: '' });
  const [advanced, setAdvanced] = useState<AdvancedRule[]>([]);
  const [byProcess, setByProcess] = useState(true);
  const [diagnostics, setDiagnostics] = useState(false);
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [acting, setActing] = useState('');
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [protocol, setProtocol] = useState('all');
  const [listening, setListening] = useState(true);
  const [live, setLive] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [portsResult, firewallResult, advancedResult] = await Promise.all([
        HttpUtil.get<Snapshot>('/api/ports'),
        HttpUtil.get<FirewallStatus>('/panel/api/server/firewall/status'),
        HttpUtil.get<AdvancedRule[]>('/api/firewall/advanced'),
      ]);
      if (portsResult.success && portsResult.obj) {
        setSnapshot(portsResult.obj);
        setError('');
      } else {
        setError(portsResult.msg);
      }
      if (firewallResult.success && firewallResult.obj) setFirewall(firewallResult.obj);
      if (advancedResult.success && advancedResult.obj) setAdvanced(advancedResult.obj);
    } catch {
      setError(ru ? 'Не удалось получить список портов' : 'Failed to read ports');
    } finally {
      setLoading(false);
    }
  }, [ru]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!live) return;
    const source = new EventSource('/api/ports/stream');
    const handler = (event: MessageEvent<string>) => {
      try {
        setSnapshot(JSON.parse(event.data) as Snapshot);
      } catch {
        // Ignore malformed transient events and keep the previous snapshot.
      }
    };
    source.addEventListener('ports', handler as EventListener);
    source.onerror = () => {
      // EventSource reconnects itself; manual refresh remains available.
    };
    return () => source.close();
  }, [live]);

  const ruleMap = useMemo(() => {
    const map = new Map<string, FirewallRule>();
    for (const rule of firewall?.rules || []) {
      if (rule.port) map.set(key(rule.port, rule.protocol), rule);
    }
    return map;
  }, [firewall]);

  const containerMap = useMemo(() => {
    const map = new Map<string, ContainerPort[]>();
    for (const item of snapshot.containers || []) {
      const k = key(item.hostPort, item.protocol);
      map.set(k, [...(map.get(k) || []), item]);
    }
    return map;
  }, [snapshot.containers]);

  async function setPortAccess(port: Port, closed: boolean) {
    const k = key(port.port, port.protocol);
    setActing(k);
    try {
      const result = await HttpUtil.post<{ rules: AdvancedRule[] }>('/api/firewall/port', { port: port.port, protocol: port.protocol, closed }, { silentSuccess: true });
      if (result.success && result.obj) { setAdvanced(result.obj.rules); await load(); }
    } finally { setActing(''); }
  }

  const closedSet = useMemo(() => new Set(advanced.filter((rule) => rule.id === `close-port-${rule.portStart}-${rule.protocol}` && rule.action === 'deny').map((rule) => key(rule.portStart || 0, rule.protocol))), [advanced]);
  const grouped = useMemo(() => {
    if (diagnostics) return snapshot.ports;
    const map = new Map<string, Port>();
    for (const port of snapshot.ports) {
      if (!port.listening || !port.processes.length) continue;
      const k = `${port.family}-${port.address}-${port.protocol}-${port.port}`;
      const old = map.get(k);
      if (old) {
        const owners = new Map([...old.processes, ...port.processes].map((owner) => [owner.pid, owner]));
        map.set(k, { ...old, processes: [...owners.values()] });
      } else map.set(k, { ...port, processes: [...port.processes] });
    }
    return [...map.values()];
  }, [snapshot.ports, diagnostics]);

  const query = search.trim().toLowerCase();
  const filtered = grouped.filter((port) => {
    if (listening && !port.listening) return false;
    if (protocol !== 'all' && port.protocol !== protocol) return false;
    const containers = containerMap.get(key(port.port, port.protocol)) || [];
    const haystack = [
      port.port,
      port.address,
      port.state,
      port.family,
      ...port.processes.flatMap((process) => [process.pid, process.name, process.executable || '']),
      ...containers.flatMap((item) => [item.containerName, item.image, item.runtime]),
    ]
      .join(' ')
      .toLowerCase();
    return !query || haystack.includes(query);
  });

  const processGroups = useMemo(() => groupPortsByProcess(filtered), [filtered]);
  const portColumns: ColumnsType<Port> = [
          { title: ru ? 'Порт' : 'Port', dataIndex: 'port', width: 90, sorter: (a, b) => a.port - b.port },
          { title: ru ? 'Протокол' : 'Protocol', dataIndex: 'protocol', width: 100, render: (v: string) => <Tag>{v.toUpperCase()}</Tag> },
          {
            title: ru ? 'Адрес' : 'Address',
            dataIndex: 'address',
            render: (value: string, port) => (
              <Space wrap>
                <Typography.Text copyable code>{value}</Typography.Text>
                <Tag>{port.family}</Tag>
                {port.loopback ? <Tag>Loopback</Tag> : null}
              </Space>
            ),
          },
          { title: ru ? 'Состояние' : 'State', dataIndex: 'state', width: 120, render: (v: string, p) => <Tag color={p.listening ? 'success' : undefined}>{v || '—'}</Tag> },
          {
            title: ru ? 'Процесс / PID' : 'Process / PID',
            render: (_, port) => port.processes.length ? (
              <Space orientation="vertical" size={2}>
                {port.processes.map((process) => (
                  <Typography.Text key={process.pid} title={process.executable}>
                    {process.name || 'process'} <Typography.Text type="secondary">PID {process.pid}</Typography.Text>
                  </Typography.Text>
                ))}
              </Space>
            ) : <Typography.Text type="secondary">{ru ? 'Нет владельца' : 'No owner'}</Typography.Text>,
          },
          {
            title: 'Container',
            render: (_, port) => {
              const items = containerMap.get(key(port.port, port.protocol)) || [];
              return items.length ? (
                <Space orientation="vertical" size={2}>
                  {items.map((item) => (
                    <Typography.Text key={`${item.runtime}-${item.containerId}`}>
                      <Tag>{item.runtime}</Tag>{item.containerName} <Typography.Text type="secondary">{item.containerPort}/{item.protocol}</Typography.Text>
                    </Typography.Text>
                  ))}
                </Space>
              ) : '—';
            },
          },
          {
            title: ru ? 'Файрволл' : 'Firewall',
            width: 190,
            fixed: screens.md ? 'right' : undefined,
            render: (_, port) => {
              if (port.loopback || !port.listening) return <Tag>{ru ? 'Локальный' : 'Local'}</Tag>;
              const k = key(port.port, port.protocol);
              const rule = ruleMap.get(k);
              const closed = closedSet.has(k);
              const protectedPort = ['panel', 'session', 'ssh'].includes(rule?.source || '');
              return (
                <Space>
                  <Tag color={!firewall?.enabled ? 'warning' : closed ? 'error' : rule?.exists ? 'success' : 'default'}>
                    {!firewall?.enabled
                      ? (ru ? 'НЕ ФИЛЬТРУЕТСЯ' : 'UNFILTERED')
                      : closed ? (ru ? 'ЗАПРЕЩЁН' : 'DENIED') : rule?.exists
                        ? (rule.source === 'service' ? 'AUTO' : 'OPEN')
                        : (ru ? 'НЕ ОПРЕДЕЛЕНО' : 'UNKNOWN')}
                  </Tag>
                  {protectedPort ? <Tag>{ru ? 'Защищён' : 'Protected'}</Tag> : (
                    <Popconfirm title={closed ? (ru ? 'Открыть порт?' : 'Open port?') : (ru ? 'Закрыть доступ к порту? Процесс продолжит работать.' : 'Block access to this port? The process will keep running.')} onConfirm={() => void setPortAccess(port, !closed)}>
                      <Button size="small" danger={!closed} disabled={!firewall?.enabled} icon={closed ? <PlusOutlined /> : <StopOutlined />} loading={acting === k}>
                        {closed ? (ru ? 'Открыть' : 'Open') : (ru ? 'Закрыть порт' : 'Close port')}
                      </Button>
                    </Popconfirm>
                  )}
                </Space>
              );
            },
          },
        ];

  const details = (ports: Port[]) => (
    <Table<Port> size="small" rowKey={(port) => `${port.family}-${port.protocol}-${port.socketId}`} dataSource={ports} loading={loading} columns={portColumns} scroll={{ x: 1180 }} pagination={{ pageSize: 20, showSizeChanger: true, hideOnSinglePage: true }} />
  );

  return (
    <Card className="panel-card">
      <Space wrap style={{ marginBottom: 16 }}>
        <Input.Search
          placeholder={ru ? 'Порт, адрес, процесс, PID или контейнер' : 'Port, address, process, PID or container'}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          style={{ width: 330 }}
          allowClear
        />
        <Select
          value={protocol}
          onChange={setProtocol}
          style={{ width: 145 }}
          options={[
            { value: 'all', label: 'TCP + UDP' },
            { value: 'tcp', label: 'TCP' },
            { value: 'udp', label: 'UDP' },
          ]}
        />
        <Space><Switch checked={byProcess} onChange={setByProcess} /><span>{ru ? 'По процессам' : 'Group by process'}</span></Space>
        <Space><Switch checked={diagnostics} onChange={(value) => { setDiagnostics(value); setListening(!value); }} /><span>{ru ? 'Все сокеты (диагностика)' : 'All sockets (diagnostics)'}</span></Space>
        <Space><Switch checked={listening} disabled={!diagnostics} onChange={setListening} /><span>{ru ? 'Только слушающие' : 'Listening only'}</span></Space>
        <Space><Switch checked={live} onChange={setLive} /><span>{ru ? 'Live' : 'Live'}</span></Space>
        <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>
          {ru ? 'Обновить' : 'Refresh'}
        </Button>
      </Space>

      {error ? <Alert type="error" showIcon title={error} style={{ marginBottom: 16 }} /> : null}

      {byProcess ? (
        <Table<ProcessGroup>
          size="small"
          rowKey="id"
          dataSource={processGroups}
          loading={loading}
          scroll={{ x: 1000 }}
          pagination={{ pageSize: 20, showSizeChanger: true }}
          expandable={{ expandedRowRender: (group) => details(group.ports) }}
          columns={[
            {
              title: ru ? 'Процесс / PID' : 'Process / PID', width: 220,
              render: (_, group) => group.processes.length ? <Space orientation="vertical" size={2}>{group.processes.map((owner) => <Typography.Text key={owner.pid} title={owner.executable}>{owner.name || 'process'} <Typography.Text type="secondary">PID {owner.pid}</Typography.Text></Typography.Text>)}</Space> : <Typography.Text type="secondary">{ru ? 'Нет владельца' : 'No owner'}</Typography.Text>,
            },
            {
              title: ru ? 'Порты и диапазоны' : 'Ports and ranges', width: 360,
              render: (_, group) => <Space orientation="vertical" size={2}>{[...new Set(group.ports.map((port) => port.protocol))].map((proto) => <div key={proto}><Tag>{proto.toUpperCase()}</Tag><Typography.Paragraph style={{ maxWidth: 310, marginBottom: 0 }} ellipsis={{ rows: 2, tooltip: true }}><Typography.Text code>{formatPortRanges(group.ports.filter((port) => port.protocol === proto).map((port) => port.port))}</Typography.Text></Typography.Paragraph></div>)}</Space>,
            },
            {
              title: ru ? 'Адреса' : 'Addresses',
              render: (_, group) => <Space wrap>{[...new Set(group.ports.map((port) => port.address))].map((address) => <Typography.Text key={address} code>{address}</Typography.Text>)}</Space>,
            },
            {
              title: ru ? 'Порты' : 'Ports', width: 90,
              render: (_, group) => new Set(group.ports.map((port) => key(port.port, port.protocol))).size,
            },
            {
              title: ru ? 'Файрволл' : 'Firewall', width: 210,
              render: (_, group) => {
                const ports = [...new Map(group.ports.filter((port) => port.listening && !port.loopback).map((port) => [key(port.port, port.protocol), port])).values()];
                if (!ports.length) return <Tag>{ru ? 'Локальный / соединения' : 'Local / connections'}</Tag>;
                if (!firewall?.enabled) return <Tag color="warning">{ru ? 'НЕ ФИЛЬТРУЕТСЯ' : 'UNFILTERED'}</Tag>;
                const denied = ports.filter((port) => closedSet.has(key(port.port, port.protocol))).length;
                return <Space wrap>{denied ? <Tag color="error">{ru ? 'Запрещено' : 'Denied'}: {denied}</Tag> : null}<Typography.Text type="secondary">{ru ? 'Раскройте для управления' : 'Expand to manage'}</Typography.Text></Space>;
              },
            },
          ]}
        />
      ) : details(filtered)}


      <Typography.Text type="secondary">
        {ru
          ? 'По умолчанию показаны слушающие TCP и привязанные UDP-сокеты с процессом-владельцем; Порты одного процесса собраны в раскрываемую строку, последовательные порты показаны диапазонами через дефис. Внутри доступны отдельные адреса, порты и действия файрволла. В диагностике доступны временные соединения и сокеты без владельца. Наличие сокета не означает доступность из интернета. Закрытие блокирует новые входящие соединения; процесс и уже установленные соединения продолжают работать.'
          : 'The default view shows owned TCP listeners and bound UDP sockets, grouped into expandable process rows with hyphen-separated consecutive port ranges. Expand a row for addresses, individual ports and firewall actions. Diagnostics includes temporary connections and sockets without an owner. A socket does not prove internet reachability. Closing blocks new incoming connections; processes and existing connections keep running.'}
      </Typography.Text>
    </Card>
  );
}
