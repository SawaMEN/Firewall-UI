import { useEffect, useState } from 'react';
import { Alert, Button, Card, Input, Select, Space, Switch, Table, Tag, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { HttpUtil } from '@/utils';

type Process = {
  pid: number;
  name: string;
  executable?: string;
};

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

export function PortsTable() {
  const { i18n } = useTranslation();
  const ru = i18n.language.startsWith('ru');
  const [ports, setPorts] = useState<Port[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [protocol, setProtocol] = useState('all');
  const [listening, setListening] = useState(true);
  const [refresh, setRefresh] = useState(true);
  const [revision, setRevision] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let active = false;

    async function update() {
      if (active) return;
      active = true;
      setLoading(true);
      try {
        const result = await HttpUtil.get<Port[]>('/api/ports');
        if (cancelled) return;
        if (result.success && result.obj) {
          setPorts(result.obj);
          setError('');
        } else {
          setError(result.msg);
        }
      } catch {
        if (!cancelled) setError(ru ? 'Не удалось получить список портов' : 'Failed to read ports');
      } finally {
        active = false;
        if (!cancelled) setLoading(false);
      }
    }

    void update();
    const timer = refresh
      ? window.setInterval(() => {
          if (!document.hidden) void update();
        }, 5000)
      : undefined;

    return () => {
      cancelled = true;
      if (timer) window.clearInterval(timer);
    };
  }, [refresh, revision, ru]);

  const query = search.trim().toLowerCase();
  const filtered = ports.filter((port) => {
    if (listening && !port.listening) return false;
    if (protocol !== 'all' && port.protocol !== protocol) return false;
    const haystack = [
      port.port,
      port.address,
      port.state,
      port.family,
      ...port.processes.flatMap((process) => [process.pid, process.name, process.executable || '']),
    ]
      .join(' ')
      .toLowerCase();
    return !query || haystack.includes(query);
  });

  return (
    <Card className="panel-card">
      <Space wrap style={{ marginBottom: 16 }}>
        <Input.Search
          placeholder={ru ? 'Порт, адрес, процесс или PID' : 'Port, address, process or PID'}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          style={{ width: 300 }}
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
        <Space>
          <Switch checked={listening} onChange={setListening} />
          <span>{ru ? 'Только слушающие' : 'Listening only'}</span>
        </Space>
        <Space>
          <Switch checked={refresh} onChange={setRefresh} />
          <span>{ru ? 'Автообновление' : 'Auto refresh'}</span>
        </Space>
        <Button
          icon={<ReloadOutlined />}
          loading={loading}
          onClick={() => setRevision((value) => value + 1)}
        >
          {ru ? 'Обновить' : 'Refresh'}
        </Button>
      </Space>

      {error ? <Alert type="error" showIcon title={error} style={{ marginBottom: 16 }} /> : null}

      <Table<Port>
        size="small"
        rowKey={(port) => `${port.family}-${port.protocol}-${port.socketId}`}
        dataSource={filtered}
        loading={loading}
        scroll={{ x: 880 }}
        pagination={{ pageSize: 20, showSizeChanger: true }}
        columns={[
          {
            title: ru ? 'Порт' : 'Port',
            dataIndex: 'port',
            width: 90,
            sorter: (a, b) => a.port - b.port,
          },
          {
            title: ru ? 'Протокол' : 'Protocol',
            dataIndex: 'protocol',
            width: 100,
            render: (value: string) => <Tag>{value.toUpperCase()}</Tag>,
          },
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
          {
            title: ru ? 'Состояние' : 'State',
            dataIndex: 'state',
            render: (value: string, port) => (
              <Tag color={port.listening ? 'success' : 'default'}>{value || '—'}</Tag>
            ),
          },
          {
            title: ru ? 'Процесс / PID' : 'Process / PID',
            render: (_, port) =>
              port.processes.length ? (
                <Space orientation="vertical" size={2}>
                  {port.processes.map((process) => (
                    <Typography.Text key={process.pid} title={process.executable}>
                      {process.name || 'process'}{' '}
                      <Typography.Text type="secondary">PID {process.pid}</Typography.Text>
                    </Typography.Text>
                  ))}
                </Space>
              ) : (
                <Typography.Text type="secondary">
                  {ru ? 'Нет владельца / недостаточно прав' : 'No owner / insufficient permissions'}
                </Typography.Text>
              ),
          },
        ]}
      />

      <Typography.Text type="secondary">
        {ru
          ? 'Показаны локальные TCP/UDP-сокеты IPv4 и IPv6. Отключите фильтр слушающих портов, чтобы увидеть активные соединения. PID и путь процесса требуют доступа к /proc.'
          : 'Local IPv4 and IPv6 TCP/UDP sockets. Disable the listening-only filter to inspect active connections. PID and executable path require access to /proc.'}
      </Typography.Text>
    </Card>
  );
}
