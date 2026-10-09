import { lazy, Suspense, useMemo, useState } from 'react';
import { ConfigProvider, Layout, Space, Spin, Typography } from 'antd';
import {
  DashboardOutlined,
  DatabaseOutlined,
  SafetyOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import AppSidebar, { type PageKey } from '@/layouts/AppSidebar';
import { useTheme } from '@/hooks/useTheme';
const DashboardPage = lazy(() => import('@/pages/dashboard/DashboardPage'));
const SettingsPage = lazy(() => import('@/pages/settings/SettingsPage'));
const FirewallManager = lazy(() => import('./FirewallManager').then(module => ({ default: module.FirewallManager })));
const PortsTable = lazy(() => import('./PortsTable').then(module => ({ default: module.PortsTable })));

export default function FirewallPage() {
  const { i18n } = useTranslation();
  const { antdThemeConfig } = useTheme();
  const [page, setPage] = useState<PageKey>('overview');
  const ru = (i18n.resolvedLanguage || i18n.language || '').toLowerCase().startsWith('ru');

  const meta = useMemo(
    () => ({
      overview: {
        icon: <DashboardOutlined />,
        title: ru ? 'Обзор' : 'Overview',
        subtitle: ru
          ? 'Состояние файрволла, публичные сервисы, контейнеры и потенциально опасные порты.'
          : 'Firewall health, public services, containers and potentially exposed ports.',
      },
      firewall: {
        icon: <SafetyOutlined />,
        title: ru ? 'Файрволл' : 'Firewall',
        subtitle: ru
          ? 'Автосинхронизация, простые правила и расширенные CIDR/allow/deny политики.'
          : 'Auto-sync, simple rules and advanced CIDR/allow/deny policies.',
      },
      ports: {
        icon: <DatabaseOutlined />,
        title: ru ? 'Порты и процессы' : 'Ports & processes',
        subtitle: ru
          ? 'Live TCP/UDP-сокеты, процессы и публикации Docker/Podman.'
          : 'Live TCP/UDP sockets, processes and Docker/Podman publications.',
      },
      settings: {
        icon: <SettingOutlined />,
        title: ru ? 'Настройки' : 'Settings',
        subtitle: ru
          ? 'Доступ к панели, CIDR allowlist, backup, история, журнал и обновления.'
          : 'Panel access, CIDR allowlist, backups, history, audit log and updates.',
      },
    }),
    [ru],
  );

  const selected = meta[page];

  return (
    <ConfigProvider theme={antdThemeConfig}>
      <Layout className="page-layout">
        <AppSidebar page={page} onPageChange={setPage} />
        <Layout className="content-shell">
          <Layout.Content id="content-layout" className="content-area">
            <div className="page-content">
              <div className="page-header">
                <div className="page-header-icon">{selected.icon}</div>
                <div>
                  <Typography.Title level={2} style={{ margin: 0 }}>
                    {selected.title}
                  </Typography.Title>
                  <Typography.Text type="secondary">{selected.subtitle}</Typography.Text>
                </div>
              </div>
              <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                <Suspense fallback={<Spin />} >
                {page === 'overview' ? <DashboardPage /> : null}
                {page === 'firewall' ? <FirewallManager /> : null}
                {page === 'ports' ? <PortsTable /> : null}
                {page === 'settings' ? <SettingsPage /> : null}
                </Suspense>
              </Space>
            </div>
          </Layout.Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
