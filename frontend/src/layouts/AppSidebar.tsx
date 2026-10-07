import { useState } from 'react';
import { Button, Drawer, Layout, Menu, Select, Space } from 'antd';
import {
  DatabaseOutlined,
  LogoutOutlined,
  MenuOutlined,
  SafetyOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { useTheme, type ThemeMode } from '@/hooks/useTheme';
import { HttpUtil } from '@/utils';
import './AppSidebar.css';

export type PageKey = 'firewall' | 'ports' | 'settings';

type Props = {
  page: PageKey;
  onPageChange: (page: PageKey) => void;
};

export default function AppSidebar({ page, onPageChange }: Props) {
  const [collapsed, setCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const { mode, setThemeMode } = useTheme();
  const { i18n } = useTranslation();
  const ru = i18n.language.startsWith('ru');

  const items = [
    { key: 'firewall', icon: <SafetyOutlined />, label: ru ? 'Файрволл' : 'Firewall' },
    { key: 'ports', icon: <DatabaseOutlined />, label: ru ? 'Порты и процессы' : 'Ports & processes' },
    { key: 'settings', icon: <SettingOutlined />, label: ru ? 'Настройки' : 'Settings' },
  ];

  const choose = (key: string) => {
    onPageChange(key as PageKey);
    setDrawerOpen(false);
  };

  const signOut = () => {
    void HttpUtil.post('/api/logout').then((result) => {
      if (result.success) window.dispatchEvent(new Event('session-expired'));
    });
  };

  const controls = (
    <Space orientation="vertical" size="small" style={{ width: '100%' }}>
      <Select
        aria-label="Theme"
        value={mode}
        onChange={(value) => setThemeMode(value as ThemeMode)}
        style={{ width: '100%' }}
        options={['light', 'dark', 'ultra-dark', 'colorful', 'blue-gray', 'cyberpunk'].map(
          (value) => ({ value, label: value }),
        )}
      />
      <Select
        aria-label="Language"
        value={ru ? 'ru' : 'en'}
        onChange={(value) => {
          localStorage.setItem('firewall-language', value);
          void i18n.changeLanguage(value);
        }}
        style={{ width: '100%' }}
        options={[
          { value: 'ru', label: 'Русский' },
          { value: 'en', label: 'English' },
        ]}
      />
      <Button icon={<LogoutOutlined />} onClick={signOut} block>
        {ru ? 'Выйти' : 'Sign out'}
      </Button>
    </Space>
  );

  return (
    <>
      <aside
        className="ant-sidebar sidebar-pinned"
        style={{ flexBasis: collapsed ? 72 : 250, ['--sider-rail' as string]: collapsed ? '72px' : '250px' }}
      >
        <Layout.Sider
          width={250}
          collapsedWidth={72}
          collapsed={collapsed}
          collapsible
          onCollapse={setCollapsed}
          breakpoint="lg"
          theme="light"
        >
          <div className="sider-brand">
            <div className="sider-brand-content">
              <span className="brand-text">
                <span className="brand-text-full">Firewall-UI</span>
                <span className="brand-text-compact">FW</span>
              </span>
            </div>
          </div>
          <Menu
            className="sider-nav"
            selectedKeys={[page]}
            mode="inline"
            items={items}
            onClick={({ key }) => choose(key)}
          />
          {!collapsed ? <div className="sider-utility">{controls}</div> : null}
        </Layout.Sider>
      </aside>

      <Button
        className="drawer-handle"
        aria-label={ru ? 'Открыть меню' : 'Open menu'}
        icon={<MenuOutlined />}
        onClick={() => setDrawerOpen(true)}
      />

      <Drawer
        placement="left"
        width={286}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        closable={false}
        styles={{ body: { padding: 0, display: 'flex', flexDirection: 'column' } }}
      >
        <div className="drawer-header">
          <span className="drawer-brand">Firewall-UI</span>
        </div>
        <Menu
          className="drawer-menu"
          selectedKeys={[page]}
          mode="inline"
          items={items}
          onClick={({ key }) => choose(key)}
        />
        <div className="drawer-utility" style={{ padding: 16 }}>{controls}</div>
      </Drawer>
    </>
  );
}
