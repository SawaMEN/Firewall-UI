import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { App as AntApp, Button, Card, message, ConfigProvider, Form, Input, Spin } from 'antd';
import ruRU from 'antd/locale/ru_RU';
import enUS from 'antd/locale/en_US';
import i18n from 'i18next';
import { initReactI18next, useTranslation } from 'react-i18next';
import { ThemeProvider, useTheme } from '@/hooks/useTheme';
import { request, setCSRF } from '@/utils';
import FirewallPage from '@/pages/firewall/FirewallPage';
import './styles/material-ui.css';
import './styles/page-shell.css';
import './styles/app.css';
void i18n.use(initReactI18next).init({ lng: localStorage.getItem('firewall-language') || 'ru', fallbackLng: 'en', resources: { ru: { translation: {} }, en: { translation: {} } }, interpolation: { escapeValue: false } });
function Application() {
 const { antdThemeConfig } = useTheme(); const { i18n } = useTranslation(); const ru = i18n.language.startsWith('ru');
 const [authenticated, setAuthenticated] = useState(false); const [loading, setLoading] = useState(true); const [busy, setBusy] = useState(false);
 useEffect(() => { const expired = () => { setCSRF(''); setAuthenticated(false); }; window.addEventListener('session-expired',expired); void request<{csrf:string}>('/api/session').then(r => { if (r.success && r.obj) { setCSRF(r.obj.csrf); setAuthenticated(true); } }).catch(() => {}).finally(() => setLoading(false));return () => window.removeEventListener('session-expired',expired); },[]);
 return <ConfigProvider theme={antdThemeConfig} locale={ru ? ruRU : enUS}><AntApp>{loading ? <div className="login-shell"><Spin /></div> : authenticated ? <FirewallPage /> : <div className="login-shell"><Card title="Firewall-UI" style={{ width: 380, maxWidth: '100%' }}><Form layout="vertical" initialValues={{ username: 'admin' }} onFinish={async values => { setBusy(true);try { const result = await request<{csrf:string}>('/api/login',values); if (result.success && result.obj) { setCSRF(result.obj.csrf);setAuthenticated(true); } } catch { void message.error(ru ? 'Не удалось связаться с сервером' : 'Server unavailable'); } finally { setBusy(false); } }}>
  <Form.Item name="username" label={ru ? 'Имя пользователя' : 'Username'} rules={[{required:true}]}><Input autoComplete="username" /></Form.Item>
  <Form.Item name="password" label={ru ? 'Пароль' : 'Password'} rules={[{required:true}]}><Input.Password autoComplete="current-password" /></Form.Item>
  <Button htmlType="submit" type="primary" block loading={busy}>{ru ? 'Войти' : 'Sign in'}</Button>
 </Form></Card></div>}</AntApp></ConfigProvider>;
}
createRoot(document.getElementById('root')!).render(<StrictMode><ThemeProvider><Application /></ThemeProvider></StrictMode>);
