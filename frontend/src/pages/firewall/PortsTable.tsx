import { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Grid, Input, Select, Space, Switch, Table, Tag, Typography } from 'antd';
import { PlusOutlined, ReloadOutlined, StopOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { HttpUtil } from '@/utils';

type Process = { pid: number; name: string; executable?: string };
type Port = {
  socketId: string;
  port: number;
  protocol: string;
  address: string;
  family: string;
  state: string;
  listening: boolean;
  loopback: boolean;
  processes: Process[];
};
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
      const [portsResult, firewallResult] = await Promise.all([
        HttpUtil.get<Snapshot>('/api/ports'),
        HttpUtil.get<FirewallStatus>('/panel/api/server/firewall/status'),
      ]);
      if (portsResult.success && portsResult.obj) {
        setSnapshot(portsResult.obj);
        setError('');
      } else {
        setError(portsResult.msg);
      }
      if (firewallResult.success && firewallResult.obj) setFirewall(firewallResult.obj);
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

  const manualSet = useMemo(
    () => new Set((firewall?.manualRules || []).map((rule) => key(rule.port, rule.protocol))),
    [firewall],
  );

  const containerMap = useMemo(() => {
    const map = new Map<string, ContainerPort[]>();
    for (const item of snapshot.containers || []) {
      const k = key(item.hostPort, item.protocol);
      map.set(k, [...(map.get(k) || []), item]);
    }
    return map;
  }, [snapshot.containers]);

  async function toggleManual(port: Port) {
    const k = key(port.port, port.protocol);
    const remove = manualSet.has(k);
    setActing(k);
    try {
      const result = await HttpUtil.post<FirewallStatus>(
        remove ? '/panel/api/server/firewall/rules/delete' : '/panel/api/server/firewall/rules/add',
        { port: port.port, protocol: port.protocol, label: port.processes[0]?.name || 'Service' },
        { silentSuccess: true },
      );
      if (result.success && result.obj) setFirewall(result.obj);
    } finally {
      setActing('');
    }
  }

  const query = search.trim().toLowerCase();
  const filtered = snapshot.ports.filter((port) => {
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
        <Space><Switch checked={listening} onChange={setListening} /><span>{ru ? 'Только слушающие' : 'Listening only'}</span></Space>
        <Space><Switch checked={live} onChange={setLive} /><span>{ru ? 'Live' : 'Live'}</span></Space>
        <Button icon={<ReloadOutlined />} loading={loading} onClick={() => void load()}>
          {ru ? 'Обновить' : 'Refresh'}
        </Button>
      </Space>

      {error ? <Alert type="error" showIcon title={error} style={{ marginBottom: 16 }} /> : null}

      <Table<Port>
        size="small"
        rowKey={(port) => `${port.family}-${port.protocol}-${port.socketId}`}
        dataSource={filtered}
        loading={loading}
        scroll={{ x: 1180 }}
        pagination={{ pageSize: 20, showSizeChanger: true }}
        columns={[
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
              const manual = manualSet.has(k);
              return (
                <Space>
                  <Tag color={!firewall?.enabled ? 'warning' : rule?.exists ? 'success' : 'error'}>
                    {!firewall?.enabled
                      ? (ru ? 'НЕ ФИЛЬТРУЕТСЯ' : 'UNFILTERED')
                      : rule?.exists
                        ? (rule.source === 'service' ? 'AUTO' : 'OPEN')
                        : 'CLOSED'}
                  </Tag>
                  {manual || !rule?.exists ? (
                    <Button
                      size="small"
                      danger={manual}
                      icon={manual ? <StopOutlined /> : <PlusOutlined />}
                      loading={acting === k}
                      onClick={() => void toggleManual(port)}
                    >
                      {manual ? (ru ? 'Убрать' : 'Remove') : (ru ? 'Разрешить' : 'Allow')}
                    </Button>
                  ) : null}
                </Space>
              );
            },
          },
        ]}
      />

      <Typography.Text type="secondary">
        {ru
          ? 'Список поступает из серверного кэша через SSE и не сканирует /proc на каждый запрос. Docker/Podman публикации сопоставляются с host-портами.'
          : 'The table is fed from a server-side cache over SSE instead of rescanning /proc per request. Docker/Podman published ports are mapped to host sockets.'}
      </Typography.Text>
    </Card>
  );
}
