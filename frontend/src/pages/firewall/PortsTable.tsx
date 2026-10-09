import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import {
  Alert,
  Button,
  Card,
  Collapse,
  Grid,
  Input,
  Pagination,
  Popconfirm,
  Select,
  Segmented,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd';
import {
  PlusOutlined,
  ReloadOutlined,
  SearchOutlined,
  StopOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { HttpUtil } from '@/utils';

import type { ColumnsType } from 'antd/es/table';
import {
  formatPortRanges,
  groupPortsByProcess,
  summarizePorts,
  type Port,
  type ProcessGroup,
} from './portGroups';

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
type Snapshot = {
  ports: Port[];
  containers: ContainerPort[];
  updatedAt: string;
};
type FirewallRule = {
  port?: number;
  protocol: string;
  source: string;
  exists: boolean;
  owned: boolean;
};
type AdvancedRule = {
  id: string;
  action: string;
  portStart?: number;
  portEnd?: number;
  protocol: string;
};
type ManualRule = { port: number; protocol: string; label?: string };
type FirewallStatus = {
  enabled: boolean;
  autoSync: boolean;
  rules: FirewallRule[];
  manualRules: ManualRule[];
};

const key = (port: number, protocol: string) => `${port}/${protocol}`;

function MobilePortList({
  ports,
  renderPort,
}: {
  ports: Port[];
  renderPort: (port: Port) => ReactNode;
}) {
  const [page, setPage] = useState(1);
  const current = Math.min(page, Math.max(1, Math.ceil(ports.length / 20)));
  return (
    <div className="mobile-port-list">
      {ports.slice((current - 1) * 20, current * 20).map(renderPort)}
      <Pagination
        simple
        hideOnSinglePage
        current={current}
        pageSize={20}
        total={ports.length}
        onChange={setPage}
      />
    </div>
  );
}

export function PortsTable() {
  const screens = Grid.useBreakpoint();
  const [mobilePage, setMobilePage] = useState(1);
  const { i18n } = useTranslation();
  const ru = i18n.language.startsWith('ru');
  const [snapshot, setSnapshot] = useState<Snapshot>({
    ports: [],
    containers: [],
    updatedAt: '',
  });
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
      if (firewallResult.success && firewallResult.obj)
        setFirewall(firewallResult.obj);
      if (advancedResult.success && advancedResult.obj)
        setAdvanced(advancedResult.obj);
    } catch {
      setError(
        ru ? 'Не удалось получить список портов' : 'Failed to read ports',
      );
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
      const result = await HttpUtil.post<{ rules: AdvancedRule[] }>(
        '/api/firewall/port',
        { port: port.port, protocol: port.protocol, closed },
        { silentSuccess: true },
      );
      if (result.success && result.obj) {
        setAdvanced(result.obj.rules);
        await load();
      }
    } finally {
      setActing('');
    }
  }

  const closedSet = useMemo(
    () =>
      new Set(
        advanced
          .filter(
            (rule) =>
              rule.id === `close-port-${rule.portStart}-${rule.protocol}` &&
              rule.action === 'deny',
          )
          .map((rule) => key(rule.portStart || 0, rule.protocol)),
      ),
    [advanced],
  );
  const grouped = useMemo(() => {
    if (diagnostics) return snapshot.ports;
    const map = new Map<string, Port>();
    for (const port of snapshot.ports) {
      if (!port.listening || !port.processes.length) continue;
      const k = `${port.family}-${port.address}-${port.protocol}-${port.port}`;
      const old = map.get(k);
      if (old) {
        const owners = new Map(
          [...old.processes, ...port.processes].map((owner) => [
            owner.pid,
            owner,
          ]),
        );
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
      ...port.processes.flatMap((process) => [
        process.pid,
        process.name,
        process.executable || '',
      ]),
      ...containers.flatMap((item) => [
        item.containerName,
        item.image,
        item.runtime,
      ]),
    ]
      .join(' ')
      .toLowerCase();
    return !query || haystack.includes(query);
  });

  const processGroups = useMemo(
    () => groupPortsByProcess(filtered),
    [filtered],
  );
  const visibleMobilePage = Math.min(
    mobilePage,
    Math.max(1, Math.ceil(processGroups.length / 20)),
  );
  const renderPortAccess = (port: Port) => {
    if (port.loopback || !port.listening)
      return <Tag>{ru ? 'Локальный' : 'Local'}</Tag>;
    const k = key(port.port, port.protocol);
    const rule = ruleMap.get(k);
    const closed = closedSet.has(k);
    const protectedPort = ['panel', 'session', 'ssh'].includes(
      rule?.source || '',
    );
    return (
      <div className="port-access">
        <Tag
          color={
            !firewall?.enabled
              ? 'warning'
              : closed
                ? 'error'
                : rule?.exists
                  ? 'success'
                  : 'default'
          }
        >
          {!firewall?.enabled
            ? ru
              ? 'НЕ ФИЛЬТРУЕТСЯ'
              : 'UNFILTERED'
            : closed
              ? ru
                ? 'ЗАПРЕЩЁН'
                : 'DENIED'
              : rule?.exists
                ? rule.source === 'service'
                  ? 'AUTO'
                  : 'OPEN'
                : ru
                  ? 'НЕ ОПРЕДЕЛЕНО'
                  : 'UNKNOWN'}
        </Tag>
        {protectedPort ? (
          <Tag>{ru ? 'Защищён' : 'Protected'}</Tag>
        ) : (
          <Popconfirm
            title={
              closed
                ? ru
                  ? 'Открыть порт?'
                  : 'Open port?'
                : ru
                  ? 'Закрыть доступ к порту? Процесс продолжит работать.'
                  : 'Block access to this port? The process will keep running.'
            }
            onConfirm={() => void setPortAccess(port, !closed)}
          >
            <Button
              size="small"
              danger={!closed}
              disabled={!firewall?.enabled}
              icon={closed ? <PlusOutlined /> : <StopOutlined />}
              loading={acting === k}
            >
              {closed
                ? ru
                  ? 'Открыть'
                  : 'Open'
                : ru
                  ? 'Закрыть порт'
                  : 'Close port'}
            </Button>
          </Popconfirm>
        )}
      </div>
    );
  };
  const portColumns: ColumnsType<Port> = [
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
      render: (v: string) => <Tag>{v.toUpperCase()}</Tag>,
    },
    {
      title: ru ? 'Адрес' : 'Address',
      dataIndex: 'address',
      width: 240,
      render: (value: string, port) => (
        <Space wrap>
          <Typography.Text copyable code>
            {value}
          </Typography.Text>
          <Tag>{port.family}</Tag>
          {port.loopback ? <Tag>Loopback</Tag> : null}
        </Space>
      ),
    },
    {
      title: ru ? 'Состояние' : 'State',
      dataIndex: 'state',
      width: 120,
      render: (v: string, p) => (
        <Tag color={p.listening ? 'success' : undefined}>{v || '—'}</Tag>
      ),
    },
    {
      key: 'process',
      title: ru ? 'Процесс / PID' : 'Process / PID',
      width: 200,
      render: (_, port) =>
        port.processes.length ? (
          <Space orientation="vertical" size={2}>
            {port.processes.map((process) => (
              <Typography.Text key={process.pid} title={process.executable}>
                {process.name || 'process'}{' '}
                <Typography.Text type="secondary">
                  PID {process.pid}
                </Typography.Text>
              </Typography.Text>
            ))}
          </Space>
        ) : (
          <Typography.Text type="secondary">
            {ru ? 'Нет владельца' : 'No owner'}
          </Typography.Text>
        ),
    },
    {
      key: 'container',
      title: ru ? 'Контейнер' : 'Container',
      width: 170,
      render: (_, port) => {
        const items = containerMap.get(key(port.port, port.protocol)) || [];
        return items.length ? (
          <Space orientation="vertical" size={2}>
            {items.map((item) => (
              <Typography.Text key={`${item.runtime}-${item.containerId}`}>
                <Tag>{item.runtime}</Tag>
                {item.containerName}{' '}
                <Typography.Text type="secondary">
                  {item.containerPort}/{item.protocol}
                </Typography.Text>
              </Typography.Text>
            ))}
          </Space>
        ) : (
          '—'
        );
      },
    },
    {
      title: ru ? 'Файрволл' : 'Firewall',
      width: 300,
      render: (_, port) => {
        return renderPortAccess(port);
      },
    },
  ];

  const details = (ports: Port[], compact = false) => (
    <div className="port-details">
      <div className="port-details-ranges">
        {[...new Set(ports.map((port) => port.protocol))].map((proto) => (
          <div key={proto}>
            <Tag>{proto.toUpperCase()}</Tag>
            <span>
              {formatPortRanges(
                ports
                  .filter((port) => port.protocol === proto)
                  .map((port) => port.port),
              )}
            </span>
          </div>
        ))}
      </div>
      {!screens.md ? (
        <MobilePortList
          ports={ports}
          renderPort={(port) => (
            <div
              className="mobile-port"
              key={`${port.family}-${port.protocol}-${port.socketId}`}
            >
              <div className="mobile-port-title">
                <strong>{port.port}</strong>
                <Tag>{port.protocol.toUpperCase()}</Tag>
                <span>{port.family}</span>
              </div>
              <div className="port-addresses">
                <span>{port.address}</span>
              </div>
              {!compact ? (
                <div className="port-owners">
                  {port.processes.map((owner) => (
                    <span key={owner.pid}>
                      {owner.name} · PID {owner.pid}
                    </span>
                  ))}
                </div>
              ) : null}
              {(containerMap.get(key(port.port, port.protocol)) || []).map(
                (container) => (
                  <Typography.Text
                    type="secondary"
                    key={`${container.runtime}-${container.containerId}`}
                  >
                    {container.runtime} · {container.containerName}
                  </Typography.Text>
                ),
              )}
              {renderPortAccess(port)}
            </div>
          )}
        />
      ) : (
        <Table<Port>
          size="small"
          tableLayout="fixed"
          rowKey={(port) => `${port.family}-${port.protocol}-${port.socketId}`}
          dataSource={ports}
          columns={portColumns.filter(
            (column) =>
              (!compact || column.key !== 'process') &&
              (column.key !== 'container' ||
                ports.some((port) =>
                  containerMap.has(key(port.port, port.protocol)),
                )),
          )}
          scroll={{ x: compact ? 850 : 1050 }}
          pagination={{
            pageSize: 20,
            showSizeChanger: true,
            hideOnSinglePage: true,
          }}
        />
      )}
    </div>
  );

  const processColumns: ColumnsType<ProcessGroup> = [
    {
      title: ru ? 'Процесс' : 'Process',
      width: 210,
      render: (_, group) => (
        <div className="port-owners">
          {group.processes.length ? (
            group.processes.map((owner) => (
              <div key={owner.pid} title={owner.executable}>
                <strong>{owner.name || 'process'}</strong>
                <span>PID {owner.pid}</span>
              </div>
            ))
          ) : (
            <Typography.Text type="secondary">
              {ru ? 'Нет владельца' : 'No owner'}
            </Typography.Text>
          )}
        </div>
      ),
    },
    {
      title: ru ? 'Диапазон портов' : 'Port range',
      width: 250,
      render: (_, group) => {
        const summary = summarizePorts(group.ports.map((port) => port.port));
        return (
          <div className="port-range-cell">
            <span className="port-range">{summary.range}</span>
            <div className="port-range-meta">
              {[...new Set(group.ports.map((port) => port.protocol))]
                .sort()
                .map((proto) => (
                  <Tag key={proto}>{proto.toUpperCase()}</Tag>
                ))}
              <Typography.Text type="secondary">
                {ru ? 'Портов' : 'Ports'}: {summary.count}
              </Typography.Text>
            </div>
            {summary.sparse ? (
              <Typography.Text className="port-range-note" type="secondary">
                {ru
                  ? 'С пропусками · точный список внутри'
                  : 'Contains gaps · expand for exact ports'}
              </Typography.Text>
            ) : null}
          </div>
        );
      },
    },
    {
      title: ru ? 'Адреса' : 'Addresses',
      width: 180,
      render: (_, group) => (
        <div className="port-addresses">
          {[...new Set(group.ports.map((port) => port.address))].map(
            (address) => (
              <span key={address}>{address}</span>
            ),
          )}
        </div>
      ),
    },
    {
      title: ru ? 'Доступ' : 'Access',
      width: 210,
      render: (_, group) => {
        const ports = [
          ...new Map(
            group.ports
              .filter((port) => port.listening && !port.loopback)
              .map((port) => [key(port.port, port.protocol), port]),
          ).values(),
        ];
        if (!ports.length) return <Tag>{ru ? 'Локальный' : 'Local'}</Tag>;
        if (!firewall?.enabled)
          return (
            <Tag color="warning">{ru ? 'Без фильтрации' : 'Unfiltered'}</Tag>
          );
        const denied = ports.filter((port) =>
          closedSet.has(key(port.port, port.protocol)),
        ).length;
        const allowed = ports.filter(
          (port) =>
            !closedSet.has(key(port.port, port.protocol)) &&
            ruleMap.get(key(port.port, port.protocol))?.exists,
        ).length;
        return (
          <div className="port-access-summary">
            {allowed ? (
              <Tag color="success">
                {ru ? 'Разрешено' : 'Allowed'}: {allowed}
              </Tag>
            ) : null}
            {denied ? (
              <Tag color="error">
                {ru ? 'Запрещено' : 'Denied'}: {denied}
              </Tag>
            ) : null}
            {ports.length > allowed + denied ? (
              <Tag>
                {ru ? 'Не определено' : 'Unknown'}:{' '}
                {ports.length - allowed - denied}
              </Tag>
            ) : null}
            <Typography.Text type="secondary">
              {ru ? 'Управление внутри списка' : 'Expand to manage'}
            </Typography.Text>
          </div>
        );
      },
    },
  ];

  return (
    <Card className="panel-card ports-panel">
      <div className="ports-heading">
        <div>
          <Typography.Title level={4}>
            {ru ? 'Активные порты' : 'Active ports'}
          </Typography.Title>
          <Typography.Text type="secondary">
            {ru
              ? 'Процессы, занятые порты и доступ через файрволл'
              : 'Processes, bound ports and firewall access'}
          </Typography.Text>
        </div>
        <div className="ports-live">
          <Switch
            size="small"
            checked={live}
            onChange={setLive}
            aria-label={ru ? 'Автообновление' : 'Live updates'}
          />
          <span>{ru ? 'Автообновление' : 'Live updates'}</span>
        </div>
      </div>
      <div className="ports-toolbar">
        <Input
          prefix={<SearchOutlined />}
          placeholder={
            ru
              ? 'Найти порт, процесс или адрес'
              : 'Find a port, process or address'
          }
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          allowClear
          aria-label={ru ? 'Поиск портов' : 'Search ports'}
        />
        <Select
          value={protocol}
          onChange={setProtocol}
          aria-label={ru ? 'Протокол' : 'Protocol'}
          options={[
            { value: 'all', label: 'TCP + UDP' },
            { value: 'tcp', label: 'TCP' },
            { value: 'udp', label: 'UDP' },
          ]}
        />
        <Select
          value={diagnostics ? (listening ? 'listeners' : 'all') : 'active'}
          onChange={(value) => {
            setDiagnostics(value !== 'active');
            setListening(value !== 'all');
          }}
          aria-label={ru ? 'Режим списка' : 'Socket visibility'}
          options={[
            { value: 'active', label: ru ? 'Активные' : 'Active' },
            {
              value: 'listeners',
              label: ru ? 'Все слушающие' : 'All listeners',
            },
            { value: 'all', label: ru ? 'Все сокеты' : 'All sockets' },
          ]}
        />
        <Button
          icon={<ReloadOutlined />}
          loading={loading}
          onClick={() => void load()}
        >
          {ru ? 'Обновить' : 'Refresh'}
        </Button>
      </div>
      <div className="ports-view-bar">
        <Segmented
          value={byProcess ? 'process' : 'port'}
          onChange={(value) => setByProcess(value === 'process')}
          options={[
            { value: 'process', label: ru ? 'По процессам' : 'By process' },
            { value: 'port', label: ru ? 'По портам' : 'By port' },
          ]}
        />
        <Typography.Text type="secondary">
          {ru ? 'Процессов' : 'Processes'}:{' '}
          {
            new Set(
              processGroups.flatMap((group) =>
                group.processes.map((owner) => owner.pid),
              ),
            ).size
          }{' '}
          · {ru ? 'Портов' : 'Ports'}:{' '}
          {new Set(filtered.map((port) => port.port)).size}
        </Typography.Text>
      </div>
      {error ? (
        <Alert
          type="error"
          showIcon
          title={error}
          style={{ marginBottom: 16 }}
        />
      ) : null}
      {byProcess && !screens.md ? (
        <div className="mobile-process-list">
          <Collapse
            items={processGroups
              .slice((visibleMobilePage - 1) * 20, visibleMobilePage * 20)
              .map((group) => {
                const summary = summarizePorts(
                  group.ports.map((port) => port.port),
                );
                return {
                  key: group.id,
                  label: (
                    <div className="mobile-process-label">
                      <div className="port-owners">
                        {group.processes.length ? (
                          group.processes.map((owner) => (
                            <div key={owner.pid}>
                              <strong>{owner.name || 'process'}</strong>
                              <span>PID {owner.pid}</span>
                            </div>
                          ))
                        ) : (
                          <span>{ru ? 'Нет владельца' : 'No owner'}</span>
                        )}
                      </div>
                      <div className="port-range-cell">
                        <span className="port-range">{summary.range}</span>
                        <span className="port-range-note">
                          {ru ? 'Портов' : 'Ports'}: {summary.count} ·{' '}
                          {[
                            ...new Set(
                              group.ports.map((port) =>
                                port.protocol.toUpperCase(),
                              ),
                            ),
                          ]
                            .sort()
                            .join(' / ')}
                        </span>
                        {summary.sparse ? (
                          <span className="port-range-note">
                            {ru ? 'С пропусками' : 'Contains gaps'}
                          </span>
                        ) : null}
                      </div>
                    </div>
                  ),
                  children: details(group.ports, true),
                };
              })}
          />
          {!processGroups.length ? (
            <Typography.Text type="secondary">
              {ru ? 'Порты не найдены' : 'No ports found'}
            </Typography.Text>
          ) : null}
          <Pagination
            simple
            hideOnSinglePage
            current={visibleMobilePage}
            pageSize={20}
            total={processGroups.length}
            onChange={setMobilePage}
          />
        </div>
      ) : byProcess ? (
        <Table<ProcessGroup>
          className="process-table"
          tableLayout="fixed"
          rowKey="id"
          dataSource={processGroups}
          loading={loading}
          scroll={{ x: 890 }}
          pagination={{
            defaultPageSize: 20,
            showSizeChanger: true,
            hideOnSinglePage: true,
          }}
          locale={{
            emptyText: ru
              ? 'Порты по выбранным фильтрам не найдены'
              : 'No ports match these filters',
          }}
          expandable={{
            columnWidth: 40,
            expandedRowRender: (group) => details(group.ports, true),
            rowExpandable: (group) => group.ports.length > 0,
          }}
          columns={processColumns}
        />
      ) : (
        details(filtered)
      )}
      <div className="ports-footnote">
        <Typography.Text type="secondary">
          {ru
            ? 'Раскройте список у процесса, чтобы посмотреть точные порты и закрыть доступ. Диапазон — минимальный и максимальный занятый порт; пропуски отмечены отдельно. Наличие порта не означает доступность из интернета.'
            : 'Expand a process to see its exact ports and block access. The range shows the lowest and highest bound port; gaps are marked separately. A bound port does not imply internet reachability.'}
        </Typography.Text>
      </div>
    </Card>
  );
}
