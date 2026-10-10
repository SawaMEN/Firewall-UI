import { StrictMode, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  App as AntApp,
  Button,
  Card,
  ConfigProvider,
  Form,
  Input,
  message,
  Spin,
} from 'antd';
import ruRU from 'antd/locale/ru_RU';
import enUS from 'antd/locale/en_US';
import i18n from 'i18next';
import { initReactI18next, useTranslation } from 'react-i18next';

import { ThemeProvider, useTheme } from '@/hooks/useTheme';
import FirewallPage from '@/pages/firewall/FirewallPage';
import { UpdateProvider } from '@/hooks/useUpdates';
import { request, setCSRF } from '@/utils';
import './styles/theme.css';
import './styles/app.css';

void i18n.use(initReactI18next).init({
  lng: localStorage.getItem('firewall-language') || 'ru',
  fallbackLng: 'en',
  resources: { ru: { translation: {} }, en: { translation: {} } },
  interpolation: { escapeValue: false },
});

type Session = { csrf: string; username?: string };
type LoginValues = { username: string; password: string };

function Application() {
  const { antdThemeConfig } = useTheme();
  const { i18n } = useTranslation();
  const ru = i18n.language.startsWith('ru');
  const [authenticated, setAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const expired = () => {
      setCSRF('');
      setAuthenticated(false);
    };
    window.addEventListener('session-expired', expired);
    void request<Session>('/api/session')
      .then((result) => {
        if (result.success && result.obj) {
          setCSRF(result.obj.csrf);
          setAuthenticated(true);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
    return () => window.removeEventListener('session-expired', expired);
  }, []);

  async function login(values: LoginValues) {
    setBusy(true);
    try {
      const result = await request<Session>('/api/login', values);
      if (result.success && result.obj) {
        // Mount protected pages only after the browser returns the cookie.
        const session = await request<Session>('/api/session');
        if (session.success && session.obj) {
          setCSRF(session.obj.csrf);
          setAuthenticated(true);
        } else {
          setCSRF('');
          void message.error(ru
            ? 'Браузер не сохранил сессию. Если включён Secure cookie, откройте панель по HTTPS. Проверьте, что cookie разрешены.'
            : 'The browser did not save the session. Use HTTPS when Secure cookie is enabled and allow cookies.');
        }
      }
    } catch {
      void message.error(ru ? 'Не удалось связаться с сервером' : 'Server unavailable');
    } finally {
      setBusy(false);
    }
  }

  return (
    <ConfigProvider theme={antdThemeConfig} locale={ru ? ruRU : enUS}>
      <AntApp>
        {loading ? (
          <div className="login-shell"><Spin /></div>
        ) : authenticated ? (
          <UpdateProvider><FirewallPage /></UpdateProvider>
        ) : (
          <div className="login-shell">
            <Card title="Firewall-UI" style={{ width: 390, maxWidth: '100%' }}>
              <Form<LoginValues>
                layout="vertical"
                initialValues={{ username: 'admin' }}
                onFinish={(values) => void login(values)}
              >
                <Form.Item name="username" label={ru ? 'Имя пользователя' : 'Username'} rules={[{ required: true }]}>
                  <Input autoComplete="username" />
                </Form.Item>
                <Form.Item name="password" label={ru ? 'Пароль' : 'Password'} rules={[{ required: true }]}>
                  <Input.Password autoComplete="current-password" />
                </Form.Item>
                <Button htmlType="submit" type="primary" block loading={busy}>
                  {ru ? 'Войти' : 'Sign in'}
                </Button>
              </Form>
            </Card>
          </div>
        )}
      </AntApp>
    </ConfigProvider>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider><Application /></ThemeProvider>
  </StrictMode>,
);
