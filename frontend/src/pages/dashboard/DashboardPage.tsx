import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Card,
  Col,
  Row,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
} from 'antd';
import { useTranslation } from 'react-i18next';
import { HttpUtil } from '@/utils';
import { usePageVisibility } from '@/hooks/usePageVisibility';
import PortRangesTable from '@/pages/firewall/PortRangesTable';
import {
  summarizePorts,
  splitPortSegments,
  type Port,
} from '@/pages/firewall/portGroups';
import { AddressLabel } from '@/pages/firewall/PortLabels';

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
type Dashboard = {
  activePorts?: Port[];
  integration?: {
    enabled: boolean;
    connected: boolean;
    message?: string;
    inbounds: number;
  };
  backend: string;
  firewallEnabled: boolean;
  autoSync: boolean;
  listeningPorts: number;
  publicPorts: number;
  managedRules: number;
  manualRules: number;
  advancedRules: number;
  containers: number;
  riskyPorts: Port[];
  containerPorts: ContainerPort[];
  lastPortScan: string;
};

export default function DashboardPage() {
  const { i18n } = useTranslation();
  const visible = usePageVisibility();
  const ru = i18n.language.startsWith('ru');
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!visible) return;
    let cancelled = false;
    let timer: number;
    const load = async () => {
      try {
        const result = await HttpUtil.get<Dashboard>('/api/dashboard');
        if (cancelled) return;
        if (result.success && result.obj) {
          const next = result.obj;
          setData((previous) =>
            previous &&
            JSON.stringify({ ...previous, lastPortScan: '' }) ===
              JSON.stringify({ ...next, lastPortScan: '' })
              ? previous
              : next,
          );
          setError('');
        } else setError(result.msg);
      } catch {
        if (!cancelled)
          setError(
            ru
              ? 'Не удалось получить состояние сервера'
              : 'Failed to read server status',
          );
      } finally {
        if (!cancelled) timer = window.setTimeout(() => void load(), 10000);
      }
    };
    void load();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [visible, ru]);

  const containerGroups = useMemo(() => {
    const groups = new Map<string, ContainerPort[]>();
    for (const port of data?.containerPorts || []) {
      const id = JSON.stringify([
        port.runtime,
        port.containerId,
        port.hostIp,
        port.protocol,
      ]);
      const group = groups.get(id);
      if (group) group.push(port);
      else groups.set(id, [port]);
    }
    return [...groups.entries()].flatMap(([id, allPorts]) =>
      splitPortSegments(allPorts, (port) => port.hostPort).map((ports) => ({
        ...ports[0],
        id: `${id}:${ports[0].hostPort}`,
        ports,
        summary: summarizePorts(ports.map((port) => port.hostPort)),
      })),
    );
  }, [data?.containerPorts]);

  if (error && !data) return <Alert type="error" showIcon title={error} />;
  if (!data)
    return <Card className="panel-card">{ru ? 'Загрузка…' : 'Loading…'}</Card>;

  const stats = [
    [
      ru ? 'Файрволл' : 'Firewall',
      data.firewallEnabled ? (ru ? 'Включён' : 'On') : ru ? 'Выключен' : 'Off',
    ],
    [ru ? 'Слушающие порты' : 'Listening ports', data.listeningPorts],
    [ru ? 'Публичные порты' : 'Public ports', data.publicPorts],
    [ru ? 'Правила' : 'Rules', data.managedRules + data.advancedRules],
    [ru ? 'Контейнеры' : 'Containers', data.containers],
  ] as const;

  return (
    <Space orientation="vertical" size="middle" style={{ width: '100%' }}>
      {error ? <Alert type="warning" showIcon title={error} /> : null}
      <Row gutter={[14, 14]}>
        {stats.map(([title, value]) => (
          <Col xs={12} md={8} xl={4} key={title}>
            <Card className="panel-card dashboard-stat">
              <Statistic title={title} value={value} />
            </Card>
          </Col>
        ))}
        <Col xs={12} md={8} xl={4}>
          <Card className="panel-card dashboard-stat">
            <Statistic title="Backend" value={data.backend || '—'} />
          </Card>
        </Col>
      </Row>

      <Card
        className="panel-card"
        title={
          ru ? 'Активные порты по приложениям' : 'Active ports by application'
        }
      >
        {data.integration?.enabled ? (
          <Alert
            style={{ marginBottom: 12 }}
            type={data.integration.connected ? 'info' : 'warning'}
            title={
              data.integration.connected
                ? `3X-UI · ${ru ? 'Инбаундов' : 'Inbounds'}: ${data.integration.inbounds}`
                : data.integration.message ||
                  (ru ? 'Подключение к 3X-UI…' : 'Connecting to 3X-UI…')
            }
          />
        ) : null}
        <PortRangesTable ports={data.activePorts || data.riskyPorts} ru={ru} />
        <Typography.Paragraph
          type="secondary"
          style={{ marginTop: 12, marginBottom: 0 }}
        >
          {ru
            ? 'В диапазон входят только подряд идущие занятые порты. Пропуски разделяют строки; точные порты, адреса и PID — в раскрытом списке.'
            : 'Ranges contain consecutive occupied ports only. Gaps split rows; expand for exact ports, addresses and PIDs.'}
        </Typography.Paragraph>
      </Card>

      <Card
        className="panel-card"
        title={
          ru
            ? 'Потенциально открытые без явного правила'
            : 'Potentially exposed without an explicit rule'
        }
      >
        {data.riskyPorts.length === 0 ? (
          <Typography.Text type="secondary">
            {ru ? 'Не обнаружено.' : 'None detected.'}
          </Typography.Text>
        ) : (
          <PortRangesTable ports={data.riskyPorts} ru={ru} />
        )}
      </Card>

      <Card
        className="panel-card"
        title={
          ru ? 'Опубликованные порты контейнеров' : 'Published container ports'
        }
      >
        <Table<(typeof containerGroups)[number]>
          size="small"
          scroll={{ x: 720 }}
          rowKey="id"
          expandable={{
            rowExpandable: (group) => group.ports.length > 1,
            expandedRowRender: (group) => (
              <Table<ContainerPort>
                size="small"
                rowKey={(p) => `${p.hostPort}-${p.containerPort}`}
                dataSource={group.ports}
                pagination={{ pageSize: 10, hideOnSinglePage: true }}
                columns={[
                  {
                    title: ru ? 'Порт сервера' : 'Host port',
                    dataIndex: 'hostPort',
                  },
                  {
                    title: ru ? 'Порт контейнера' : 'Container port',
                    dataIndex: 'containerPort',
                  },
                  {
                    title: ru ? 'Протокол' : 'Protocol',
                    dataIndex: 'protocol',
                  },
                ]}
              />
            ),
          }}
          dataSource={containerGroups}
          pagination={{ pageSize: 10, hideOnSinglePage: true }}
          locale={{
            emptyText: ru
              ? 'Docker/Podman порты не найдены'
              : 'No Docker/Podman ports found',
          }}
          columns={[
            {
              title: ru ? 'Контейнер' : 'Container',
              dataIndex: 'containerName',
            },
            { title: 'Image', dataIndex: 'image', ellipsis: true },
            {
              title: ru ? 'Публикация' : 'Published',
              render: (_, p) => (
                <Space wrap>
                  <Tag>{p.runtime}</Tag>
                  <strong className="port-range">
                    {p.summary.range}/{p.protocol.toUpperCase()}
                  </strong>
                  <AddressLabel
                    address={p.hostIp || '0.0.0.0'}
                    family={p.hostIp.includes(':') ? 'IPv6' : 'IPv4'}
                    ru={ru}
                  />
                  {p.summary.sparse ? (
                    <Typography.Text type="secondary">
                      {ru ? 'С пропусками' : 'With gaps'}
                    </Typography.Text>
                  ) : null}
                  {p.public ? (
                    <Tag color="warning">{ru ? 'Публичный' : 'Public'}</Tag>
                  ) : null}
                </Space>
              ),
            },
          ]}
        />
      </Card>
    </Space>
  );
}
