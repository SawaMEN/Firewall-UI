import { useMemo, useState } from 'react';
import { ConfigProvider, Layout, Space, Typography } from 'antd';
import { DatabaseOutlined, SafetyOutlined, SettingOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import AppSidebar, { type PageKey } from '@/layouts/AppSidebar';
import { useTheme } from '@/hooks/useTheme';
import SettingsPage from '@/pages/settings/SettingsPage';
import { FirewallManager } from './FirewallManager';
import { PortsTable } from './PortsTable';

export default function FirewallPage() {
  const { i18n } = useTranslation();
  const { antdThemeConfig } = useTheme();
  const [page, setPage] = useState<PageKey>('firewall');
  const ru = (i18n.resolvedLanguage || i18n.language || '').toLowerCase().startsWith('ru');

  const meta = useMemo(
    () => ({
      firewall: {
        icon: <SafetyOutlined />,
        title: ru ? 'Файрволл' : 'Firewall',
        subtitle: ru
          ? 'Управление системным файрволлом, автоматической синхронизацией и ручными правилами.'
          : 'Manage the system firewall, automatic synchronization, and manual rules.',
      },
      ports: {
        icon: <DatabaseOutlined />,
        title: ru ? 'Порты и процессы' : 'Ports & processes',
        subtitle: ru
          ? 'Все локальные TCP/UDP-сокеты IPv4/IPv6 и процессы, которые их используют.'
          : 'All local IPv4/IPv6 TCP/UDP sockets and the processes that own them.',
      },
      settings: {
        icon: <SettingOutlined />,
        title: ru ? 'Настройки' : 'Settings',
        subtitle: ru
          ? 'Параметры доступа к веб-панели и безопасный перезапуск сервиса.'
          : 'Web-panel access settings and safe service restart.',
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
                {page === 'firewall' ? <FirewallManager /> : null}
                {page === 'ports' ? <PortsTable /> : null}
                {page === 'settings' ? <SettingsPage /> : null}
              </Space>
            </div>
          </Layout.Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
