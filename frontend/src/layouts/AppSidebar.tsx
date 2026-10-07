import { useState } from 'react';
import { Button, Layout, Menu, Select, Space } from 'antd';
import { SafetyOutlined, LogoutOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { useTheme, type ThemeMode } from '@/hooks/useTheme';
import { HttpUtil } from '@/utils';
import './AppSidebar.css';
export default function AppSidebar() {
 const [collapsed, setCollapsed] = useState(false); const { mode, setThemeMode } = useTheme();
 const { i18n } = useTranslation(); const ru = i18n.language.startsWith('ru');
 return <aside className="ant-sidebar sidebar-pinned" style={{ flexBasis: collapsed ? 72 : 250 }}><Layout.Sider width={250} collapsedWidth={72} collapsed={collapsed} collapsible onCollapse={setCollapsed} breakpoint="lg" theme="light">
   <div className="sider-brand" style={{ padding: 0 }}><span className="brand-text">{collapsed ? 'FW' : 'Firewall-UI'}</span></div>
   <Menu selectedKeys={['firewall']} items={[{ key: 'firewall', icon: <SafetyOutlined />, label: ru ? 'Файрволл' : 'Firewall' }]} />
   {!collapsed && <Space orientation="vertical" style={{ padding: 16, marginTop: 'auto' }}>
     <Select aria-label="Theme" value={mode} onChange={v => setThemeMode(v as ThemeMode)} style={{ width: 218 }} options={['light','dark','ultra-dark','colorful','blue-gray','cyberpunk'].map(value => ({ value, label: value }))} />
     <Select aria-label="Language" value={ru ? 'ru' : 'en'} onChange={v => { localStorage.setItem('firewall-language',v); void i18n.changeLanguage(v); }} style={{ width: 218 }} options={[{ value: 'ru', label: 'Русский' }, { value: 'en', label: 'English' }]} />
     <Button icon={<LogoutOutlined />} onClick={() => { void HttpUtil.post('/api/logout').then(result => { if (result.success) window.dispatchEvent(new Event('session-expired')); }); }}>{ru ? 'Выйти' : 'Sign out'}</Button>
   </Space>}
 </Layout.Sider></aside>;
}
