import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Divider,
  Input,
  InputNumber,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { HttpUtil } from '@/utils';

type FirewallRule = {
  port?: number;
  portRange?: string;
  protocol: string;
  source: string;
  label: string;
  owned: boolean;
  exists: boolean;
};
type FirewallManualRule = { port: number; protocol: string; label?: string };
type FirewallStatus = {
  supported: boolean;
  backend: string;
  enabled: boolean;
  autoSync: boolean;
  pingEnabled: boolean;
  canInstallUfw?: boolean;
  rules: FirewallRule[];
  manualRules: FirewallManualRule[];
  message?: string;
};
type AdvancedRule = {
  id: string;
  action: 'allow' | 'deny';
  protocol: 'tcp' | 'udp' | 'any';
  portStart?: number;
  portEnd?: number;
  sourceCidr?: string;
  interface?: string;
  ipVersion?: 'any' | 'ipv4' | 'ipv6';
  label?: string;
  priority: number;
};
type AdvancedResponse = { rules: AdvancedRule[] };

function portLabel(rule: FirewallRule) {
  return rule.portRange || String(rule.port || '');
}

export function FirewallManager() {
  const { i18n } = useTranslation();
  const ru = i18n.language.startsWith('ru');
  const [status, setStatus] = useState<FirewallStatus | null>(null);
  const [advanced, setAdvanced] = useState<AdvancedRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [action, setAction] = useState('');
  const [basicPort, setBasicPort] = useState<number | null>(null);
  const [basicProtocol, setBasicProtocol] = useState('both');
  const [basicLabel, setBasicLabel] = useState('');
  const [draft, setDraft] = useState<Partial<AdvancedRule>>({
    action: 'allow',
    protocol: 'tcp',
    ipVersion: 'any',
    priority: 100,
  });

  const text = useMemo(() => ru ? {
    load: 'Получение состояния файрволла…',
    failed: 'Не удалось получить состояние файрволла.',
    noFirewall: 'Поддерживаемый файрволл не найден.',
    install: 'Установить UFW',
    enabled: 'Файрволл включён',
    disabled: 'Файрволл выключен',
    auto: 'Автоматически открывать порты слушающих сервисов',
    ping: 'Разрешить ping',
    sync: 'Синхронизировать',
    safety: 'Порт панели и SSH защищаются автоматически. Опасные изменения откатываются, если UI не подтвердит доступность.',
    activeRules: 'Активные и ожидаемые правила',
    manual: 'Простые ручные правила',
    advanced: 'Расширенные правила',
    advancedHint: 'CIDR, allow/deny, диапазоны портов, IPv4/IPv6, интерфейс и приоритет. Firewalld не поддерживает поле интерфейса в этом режиме.',
    add: 'Добавить',
    remove: 'Удалить',
    port: 'Порт',
    protocol: 'Протокол',
    label: 'Описание',
    source: 'Источник',
    state: 'Состояние',
    sourceCidr: 'Source CIDR / IP',
    iface: 'Интерфейс',
    action: 'Действие',
    range: 'Диапазон',
    family: 'IP',
    priority: 'Приоритет',
    allow: 'Разрешить',
    deny: 'Запретить',
  } : {
    load: 'Loading firewall status…',
    failed: 'Failed to load firewall status.',
    noFirewall: 'No supported firewall was found.',
    install: 'Install UFW',
    enabled: 'Firewall enabled',
    disabled: 'Firewall disabled',
    auto: 'Automatically open listening service ports',
    ping: 'Allow ping',
    sync: 'Sync now',
    safety: 'Panel and SSH ports are protected automatically. Risky changes roll back if the UI cannot confirm connectivity.',
    activeRules: 'Active and expected rules',
    manual: 'Simple manual rules',
    advanced: 'Advanced rules',
    advancedHint: 'CIDR, allow/deny, port ranges, IPv4/IPv6, interface and priority. Firewalld does not support the interface field in this mode.',
    add: 'Add',
    remove: 'Delete',
    port: 'Port',
    protocol: 'Protocol',
    label: 'Description',
    source: 'Source',
    state: 'State',
    sourceCidr: 'Source CIDR / IP',
    iface: 'Interface',
    action: 'Action',
    range: 'Range',
    family: 'IP',
    priority: 'Priority',
    allow: 'Allow',
    deny: 'Deny',
  }, [ru]);

  async function load() {
    setLoading(true);
    try {
      const [statusResult, advancedResult] = await Promise.all([
        HttpUtil.get<FirewallStatus>('/panel/api/server/firewall/status'),
        HttpUtil.get<AdvancedRule[]>('/api/firewall/advanced'),
      ]);
      if (statusResult.success && statusResult.obj) setStatus(statusResult.obj);
      if (advancedResult.success && advancedResult.obj) setAdvanced(advancedResult.obj);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []);

  async function mutate(path: string, data: Record<string, unknown>, key: string) {
    setAction(key);
    try {
      const result = await HttpUtil.post<FirewallStatus>(path, data, { silentSuccess: true });
      if (result.success && result.obj) setStatus(result.obj);
      return result.success;
    } finally {
      setAction('');
    }
  }

  async function setPortAccess(port: number, protocol: string, closed: boolean) {
    setAction(`port-${port}-${protocol}`);
    try {
      const result = await HttpUtil.post('/api/firewall/port', { port, protocol, closed });
      if (result.success) await load();
    } finally { setAction(''); }
  }

  async function addAdvanced() {
    setAction('advanced-add');
    try {
      const result = await HttpUtil.post<AdvancedResponse>('/api/firewall/advanced', {
        action: draft.action || 'allow',
        protocol: draft.protocol || 'tcp',
        portStart: draft.portStart || 0,
        portEnd: draft.portEnd || draft.portStart || 0,
        sourceCidr: draft.sourceCidr || '',
        interface: draft.interface || '',
        ipVersion: draft.ipVersion || 'any',
        label: draft.label || '',
        priority: draft.priority ?? 100,
      });
      if (result.success && result.obj) {
        setAdvanced(result.obj.rules);
        setDraft({ action: 'allow', protocol: 'tcp', ipVersion: 'any', priority: 100 });
      }
    } finally {
      setAction('');
    }
  }

  async function deleteAdvanced(id: string) {
    setAction(`advanced-${id}`);
    try {
      const result = await HttpUtil.post<AdvancedResponse>('/api/firewall/advanced/delete', { id });
      if (result.success && result.obj) setAdvanced(result.obj.rules);
    } finally {
      setAction('');
    }
  }

  if (!status) {
    return loading ? <Typography.Text type="secondary">{text.load}</Typography.Text> : <Alert type="error" showIcon title={text.failed} />;
  }

  if (!status.supported) {
    return (
      <Alert
        type="warning"
        showIcon
        title={status.canInstallUfw ? text.noFirewall : status.message || text.failed}
        description={status.canInstallUfw ? (
          <Button type="primary" loading={action === 'install'} onClick={() => void mutate('/panel/api/server/firewall/install-ufw', {}, 'install')}>
            {text.install}
          </Button>
        ) : null}
      />
    );
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Card className="panel-card">
        <Space size="large" wrap>
          <Space>
            <Switch
              checked={status.enabled}
              loading={action === 'enabled'}
              onChange={(enabled) => void mutate('/panel/api/server/firewall/enabled', { enabled }, 'enabled')}
            />
            <Typography.Text strong>{status.enabled ? text.enabled : text.disabled}</Typography.Text>
          </Space>
          <Tag>{status.backend}</Tag>
          <Button loading={action === 'sync'} onClick={() => void mutate('/panel/api/server/firewall/sync', {}, 'sync')}>{text.sync}</Button>
        </Space>
        <Alert type="info" showIcon title={text.safety} style={{ marginTop: 16 }} />
        <div className="firewall-toggle-grid">
          <Space align="start">
            <Switch
              checked={status.autoSync}
              loading={action === 'auto'}
              onChange={(enabled) => void mutate('/panel/api/server/firewall/auto-sync', { enabled }, 'auto')}
            />
            <Typography.Text>{text.auto}</Typography.Text>
          </Space>
          <Space align="start">
            <Switch
              checked={status.pingEnabled}
              disabled={!status.enabled}
              loading={action === 'ping'}
              onChange={(enabled) => void mutate('/panel/api/server/firewall/ping', { enabled }, 'ping')}
            />
            <Typography.Text>{text.ping}</Typography.Text>
          </Space>
        </div>
      </Card>

      <Card className="panel-card" title={text.activeRules}>
        <Table<FirewallRule>
          size="small"
          rowKey={(rule) => `${portLabel(rule)}-${rule.protocol}-${rule.source}`}
          dataSource={status.rules || []}
          pagination={false}
          scroll={{ x: 700 }}
          columns={[
            { title: text.port, render: (_, rule) => portLabel(rule), width: 130 },
            { title: text.protocol, dataIndex: 'protocol', width: 100, render: (value: string) => <Tag>{value.toUpperCase()}</Tag> },
            { title: text.source, render: (_, rule) => rule.label || rule.source },
            {
              title: text.state,
              width: 180,
              render: (_, rule) => (
                <Space>
                  <Tag color={advanced.some((item) => item.id === `close-port-${rule.port}-${rule.protocol}`) ? 'error' : rule.exists ? 'success' : 'warning'}>{advanced.some((item) => item.id === `close-port-${rule.port}-${rule.protocol}`) ? (ru ? 'ЗАПРЕЩЁН' : 'DENIED') : rule.exists ? 'OPEN' : 'MISSING'}</Tag>
                  {rule.exists ? <Tag>{rule.owned ? 'Firewall-UI' : 'External'}</Tag> : null}
                </Space>
              ),
            },
            {
              title: '', width: 150,
              render: (_, rule) => {
                if (!rule.port || ['panel', 'session', 'ssh'].includes(rule.source)) return <Tag>{ru ? 'Защищён' : 'Protected'}</Tag>;
                const closed = advanced.some((item) => item.id === `close-port-${rule.port}-${rule.protocol}`);
                return <Popconfirm title={closed ? (ru ? 'Открыть порт?' : 'Open port?') : (ru ? 'Закрыть доступ к порту?' : 'Close access to the port?')} onConfirm={() => void setPortAccess(rule.port!, rule.protocol, !closed)}><Button size="small" danger={!closed} disabled={!status.enabled} loading={action === `port-${rule.port}-${rule.protocol}`}>{closed ? (ru ? 'Открыть' : 'Open') : (ru ? 'Закрыть порт' : 'Close port')}</Button></Popconfirm>;
              },
            },
          ]}
        />
      </Card>

      <Card className="panel-card" title={text.manual}>
        <Space wrap style={{ marginBottom: 14 }}>
          <InputNumber min={1} max={65535} value={basicPort} placeholder={text.port} onChange={setBasicPort} />
          <Select
            value={basicProtocol}
            onChange={setBasicProtocol}
            style={{ width: 135 }}
            options={[{ value: 'both', label: 'TCP + UDP' }, { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]}
          />
          <Input value={basicLabel} placeholder={text.label} maxLength={120} onChange={(event) => setBasicLabel(event.target.value)} style={{ width: 280 }} />
          <Button
            type="primary"
            icon={<PlusOutlined />}
            disabled={!basicPort}
            loading={action === 'basic-add'}
            onClick={() => {
              if (!basicPort) return;
              void mutate('/panel/api/server/firewall/rules/add', { port: basicPort, protocol: basicProtocol, label: basicLabel }, 'basic-add').then((ok) => {
                if (ok) { setBasicPort(null); setBasicLabel(''); }
              });
            }}
          >{text.add}</Button>
        </Space>
        <Table<FirewallManualRule>
          size="small"
          pagination={false}
          rowKey={(rule) => `${rule.port}-${rule.protocol}`}
          dataSource={status.manualRules || []}
          columns={[
            { title: text.port, dataIndex: 'port', width: 100 },
            { title: text.protocol, dataIndex: 'protocol', width: 110, render: (v: string) => <Tag>{v.toUpperCase()}</Tag> },
            { title: text.label, dataIndex: 'label', render: (v?: string) => v || '—' },
            {
              title: '',
              width: 100,
              render: (_, rule) => (
                <Popconfirm title={ru ? 'Удалить правило?' : 'Delete rule?'} onConfirm={() => void mutate('/panel/api/server/firewall/rules/delete', { port: rule.port, protocol: rule.protocol }, `basic-${rule.port}-${rule.protocol}`)}>
                  <Button danger size="small">{text.remove}</Button>
                </Popconfirm>
              ),
            },
          ]}
        />
      </Card>

      <Card className="panel-card" title={text.advanced}>
        <Alert type="info" showIcon title={text.advancedHint} style={{ marginBottom: 16 }} />
        <div className="advanced-rule-grid">
          <Select
            value={draft.action}
            onChange={(value) => setDraft((old) => ({ ...old, action: value }))}
            options={[{ value: 'allow', label: text.allow }, { value: 'deny', label: text.deny }]}
          />
          <Select
            value={draft.protocol}
            onChange={(value) => setDraft((old) => ({ ...old, protocol: value }))}
            options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'any', label: 'ANY' }]}
          />
          <InputNumber min={1} max={65535} value={draft.portStart} placeholder={ru ? 'Порт от' : 'Port from'} onChange={(value) => setDraft((old) => ({ ...old, portStart: value || undefined }))} />
          <InputNumber min={1} max={65535} value={draft.portEnd} placeholder={ru ? 'Порт до' : 'Port to'} onChange={(value) => setDraft((old) => ({ ...old, portEnd: value || undefined }))} />
          <Input value={draft.sourceCidr} placeholder={text.sourceCidr} onChange={(event) => setDraft((old) => ({ ...old, sourceCidr: event.target.value }))} />
          <Input value={draft.interface} placeholder={text.iface} onChange={(event) => setDraft((old) => ({ ...old, interface: event.target.value }))} />
          <Select
            value={draft.ipVersion}
            onChange={(value) => setDraft((old) => ({ ...old, ipVersion: value }))}
            options={[{ value: 'any', label: 'IPv4 + IPv6' }, { value: 'ipv4', label: 'IPv4' }, { value: 'ipv6', label: 'IPv6' }]}
          />
          <InputNumber min={-1000} max={1000} value={draft.priority} placeholder={text.priority} onChange={(value) => setDraft((old) => ({ ...old, priority: value ?? 100 }))} />
          <Input value={draft.label} placeholder={text.label} onChange={(event) => setDraft((old) => ({ ...old, label: event.target.value }))} />
          <Button type="primary" icon={<PlusOutlined />} loading={action === 'advanced-add'} onClick={() => void addAdvanced()}>{text.add}</Button>
        </div>

        <Divider />
        <Table<AdvancedRule>
          size="small"
          rowKey="id"
          dataSource={advanced}
          pagination={false}
          scroll={{ x: 1000 }}
          columns={[
            { title: text.action, dataIndex: 'action', width: 100, render: (value: string) => <Tag color={value === 'deny' ? 'error' : 'success'}>{value.toUpperCase()}</Tag> },
            { title: text.protocol, dataIndex: 'protocol', width: 100, render: (value: string) => <Tag>{value.toUpperCase()}</Tag> },
            { title: text.range, render: (_, rule) => rule.portStart ? (rule.portEnd && rule.portEnd !== rule.portStart ? `${rule.portStart}-${rule.portEnd}` : rule.portStart) : 'ANY', width: 120 },
            { title: text.sourceCidr, dataIndex: 'sourceCidr', render: (value?: string) => value || 'ANY' },
            { title: text.iface, dataIndex: 'interface', render: (value?: string) => value || 'ANY', width: 120 },
            { title: text.family, dataIndex: 'ipVersion', width: 100 },
            { title: text.priority, dataIndex: 'priority', width: 90 },
            { title: text.label, dataIndex: 'label', ellipsis: true },
            {
              title: '',
              width: 100,
              fixed: 'right',
              render: (_, rule) => (
                <Popconfirm title={ru ? 'Удалить расширенное правило?' : 'Delete advanced rule?'} onConfirm={() => void deleteAdvanced(rule.id)}>
                  <Button danger size="small" loading={action === `advanced-${rule.id}`}>{text.remove}</Button>
                </Popconfirm>
              ),
            },
          ]}
        />
      </Card>
    </Space>
  );
}
