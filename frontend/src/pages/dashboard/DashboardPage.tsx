import { useEffect, useState } from 'react';
import { Alert, Card, Col, Row, Space, Statistic, Table, Tag, Typography } from 'antd';
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
type Dashboard = {
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
  const ru = i18n.language.startsWith('ru');
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      const result = await HttpUtil.get<Dashboard>('/api/dashboard');
      if (cancelled) return;
      if (result.success && result.obj) {
        setData(result.obj);
        setError('');
      } else {
        setError(result.msg);
      }
    };
    void load();
    const timer = window.setInterval(() => void load(), 5000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  if (error) return <Alert type="error" showIcon title={error} />;
  if (!data) return <Card className="panel-card">{ru ? 'Загрузка…' : 'Loading…'}</Card>;

  const stats = [
    [ru ? 'Файрволл' : 'Firewall', data.firewallEnabled ? (ru ? 'Включён' : 'On') : (ru ? 'Выключен' : 'Off')],
    [ru ? 'Слушающие порты' : 'Listening ports', data.listeningPorts],
    [ru ? 'Публичные порты' : 'Public ports', data.publicPorts],
    [ru ? 'Правила' : 'Rules', data.managedRules + data.advancedRules],
    [ru ? 'Контейнеры' : 'Containers', data.containers],
  ] as const;

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
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
        title={ru ? 'Потенциально открытые без явного правила' : 'Potentially exposed without an explicit rule'}
      >
        {data.riskyPorts.length === 0 ? (
          <Typography.Text type="secondary">
            {ru ? 'Не обнаружено.' : 'None detected.'}
          </Typography.Text>
        ) : (
          <Table<Port>
            size="small"
            pagination={false}
            rowKey={(p) => p.socketId}
            dataSource={data.riskyPorts}
            columns={[
              { title: ru ? 'Порт' : 'Port', dataIndex: 'port', width: 90 },
              {
                title: ru ? 'Протокол' : 'Protocol',
                dataIndex: 'protocol',
                width: 100,
                render: (v: string) => <Tag>{v.toUpperCase()}</Tag>,
              },
              { title: ru ? 'Адрес' : 'Address', dataIndex: 'address' },
              {
                title: ru ? 'Процесс' : 'Process',
                render: (_, p) => p.processes.map((x) => x.name || \`PID \${x.pid}\`).join(', ') || '—',
              },
            ]}
          />
        )}
      </Card>

      <Card className="panel-card" title={ru ? 'Опубликованные порты контейнеров' : 'Published container ports'}>
        <Table<ContainerPort>
          size="small"
          rowKey={(p) => \`\${p.runtime}-\${p.containerId}-\${p.hostPort}-\${p.protocol}\`}
          dataSource={data.containerPorts}
          pagination={{ pageSize: 10, hideOnSinglePage: true }}
          locale={{ emptyText: ru ? 'Docker/Podman порты не найдены' : 'No Docker/Podman ports found' }}
          columns={[
            { title: ru ? 'Контейнер' : 'Container', dataIndex: 'containerName' },
            { title: 'Image', dataIndex: 'image', ellipsis: true },
            {
              title: ru ? 'Публикация' : 'Published',
              render: (_, p) => (
                <Space wrap>
                  <Tag>{p.runtime}</Tag>
                  <Typography.Text code>
                    {p.hostIp || '0.0.0.0'}:{p.hostPort} → {p.containerPort}/{p.protocol}
                  </Typography.Text>
                  {p.public ? <Tag color="warning">{ru ? 'Публичный' : 'Public'}</Tag> : null}
                </Space>
              ),
            },
          ]}
        />
      </Card>
    </Space>
  );
}
