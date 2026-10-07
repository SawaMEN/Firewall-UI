import { useEffect, useState } from 'react';
import { Alert, Button, Divider, Input, Select, Space, Switch, Table, Tag, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { HttpUtil } from '@/utils';

type Process = { pid: number; name: string; executable?: string };
type Port = { socketId: string; port: number; protocol: string; address: string; family: string; state: string; listening: boolean; loopback: boolean; processes: Process[] };
export function PortsTable() {
  const { i18n } = useTranslation(); const ru = i18n.language.startsWith('ru');
  const [ports, setPorts] = useState<Port[]>([]); const [loading, setLoading] = useState(false);
  const [error, setError] = useState(''); const [search, setSearch] = useState('');
  const [protocol, setProtocol] = useState('all'); const [listening, setListening] = useState(true);
  const [refresh, setRefresh] = useState(true); const [revision, setRevision] = useState(0);
  useEffect(() => {
    let cancelled = false; let active = false;
    async function update() {
      if (active) return; active = true; setLoading(true);
      try { const result = await HttpUtil.get<Port[]>('/api/ports'); if (!cancelled) { if (result.success && result.obj) { setPorts(result.obj); setError(''); } else setError(result.msg); } }
      catch { if (!cancelled) setError(ru ? 'Не удалось получить список портов' : 'Failed to read ports'); }
      finally { active = false; if (!cancelled) setLoading(false); }
    }
    void update(); const timer = refresh ? window.setInterval(() => { if (!document.hidden) void update(); }, 5000) : undefined;
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [refresh, revision, ru]);
  const filtered = ports.filter(p => (!listening || p.listening) && (protocol === 'all' || p.protocol === protocol) && `${p.port} ${p.address} ${p.state} ${p.processes.map(x => `${x.pid} ${x.name} ${x.executable || ''}`).join(' ')}`.toLowerCase().includes(search.toLowerCase()));
  return <>
    <Divider titlePlacement="start">{ru ? 'Порты и процессы сервера' : 'Server ports and processes'}</Divider>
    <Space wrap style={{ marginBottom: 16 }}>
      <Input.Search placeholder={ru ? 'Порт, адрес, процесс или PID' : 'Port, address, process or PID'} value={search} onChange={e => setSearch(e.target.value)} style={{ width: 290 }} allowClear />
      <Select value={protocol} onChange={setProtocol} style={{ width: 140 }} options={[{ value: 'all', label: 'TCP + UDP' }, { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]} />
      <Space><Switch checked={listening} onChange={setListening} /><span>{ru ? 'Только слушающие' : 'Listening only'}</span></Space>
      <Space><Switch checked={refresh} onChange={setRefresh} /><span>{ru ? 'Автообновление' : 'Auto refresh'}</span></Space>
      <Button icon={<ReloadOutlined />} loading={loading} onClick={() => setRevision(n => n + 1)}>{ru ? 'Обновить' : 'Refresh'}</Button>
    </Space>
    {error && <Alert type="error" showIcon title={error} style={{ marginBottom: 16 }} />}
    <Table<Port> size="small" rowKey={p => `${p.family}-${p.protocol}-${p.socketId}`} dataSource={filtered} loading={loading} scroll={{ x: 880 }} pagination={{ pageSize: 20, showSizeChanger: true }} columns={[
      { title: ru ? 'Порт' : 'Port', dataIndex: 'port', width: 90, sorter: (a,b) => a.port-b.port },
      { title: ru ? 'Протокол' : 'Protocol', dataIndex: 'protocol', width: 100, render: (v: string) => <Tag>{v.toUpperCase()}</Tag> },
      { title: ru ? 'Адрес' : 'Address', dataIndex: 'address', render: (v: string,p) => <Space wrap><Typography.Text copyable code>{v}</Typography.Text><Tag>{p.family}</Tag>{p.loopback && <Tag>Loopback</Tag>}</Space> },
      { title: ru ? 'Состояние' : 'State', dataIndex: 'state', render: (v: string,p) => <Tag color={p.listening ? 'success' : 'default'}>{v}</Tag> },
      { title: ru ? 'Процесс / PID' : 'Process / PID', render: (_,p) => p.processes.length ? <Space orientation="vertical" size={2}>{p.processes.map(x => <Typography.Text key={x.pid} title={x.executable}>{x.name} <Typography.Text type="secondary">PID {x.pid}</Typography.Text></Typography.Text>)}</Space> : <Typography.Text type="secondary">{ru ? 'Нет владельца / недостаточно прав' : 'No owner / insufficient permissions'}</Typography.Text> },
    ]} />
    <Typography.Text type="secondary">{ru ? 'Все локальные TCP/UDP-сокеты, IPv4 и IPv6. Включите все состояния для просмотра установленных соединений. PID и путь доступны при наличии прав на /proc.' : 'All local TCP/UDP sockets, IPv4 and IPv6. Disable listening-only to see established connections. Process details require access to /proc.'}</Typography.Text>
  </>;
}
