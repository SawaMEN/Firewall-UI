import { useEffect, useState } from 'react';
import { Alert, Button, Card, Input, Space, Switch, Typography } from 'antd';
import { HttpUtil } from '@/utils';

type Connection = {
  enabled: boolean;
  url: string;
  tokenConfigured: boolean;
  status?: { connected: boolean; message?: string; inbounds: number };
};
export default function XUISettings({ ru }: { ru: boolean }) {
  const [connection, setConnection] = useState<Connection>({
    enabled: false,
    url: '',
    tokenConfigured: false,
  });
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState('');
  const [notice, setNotice] = useState<{ error: boolean; text: string } | null>(
    null,
  );
  useEffect(() => {
    let cancelled = false;
    void HttpUtil.get<Connection>('/api/integrations/3x-ui').then((result) => {
      if (cancelled) return;
      if (result.success && result.obj) setConnection(result.obj);
      else setNotice({ error: true, text: result.msg });
    });
    return () => {
      cancelled = true;
    };
  }, []);
  async function act(action: 'save' | 'test' | 'clear') {
    setBusy(action);
    setNotice(null);
    try {
      const result = await HttpUtil.post<
        Connection & { connected?: boolean; inbounds?: number }
      >(
        action === 'test'
          ? '/api/integrations/3x-ui/test'
          : '/api/integrations/3x-ui',
        {
          enabled: action === 'clear' ? false : connection.enabled,
          url: connection.url,
          token: action === 'clear' ? '' : token,
          clearToken: action === 'clear',
        },
      );
      if (!result.success || !result.obj) {
        setNotice({ error: true, text: result.msg });
        return;
      }
      if (action !== 'test') {
        setConnection(result.obj);
        setToken('');
      }
      setNotice({
        error: false,
        text:
          action === 'test'
            ? `${ru ? 'Соединение работает. Локальных активных инбаундов' : 'Connection works. Active local inbounds'}: ${result.obj.inbounds}`
            : ru
              ? 'Настройки сохранены. Данные обновятся в течение 30 секунд.'
              : 'Saved. Metadata refreshes within 30 seconds.',
      });
    } finally {
      setBusy('');
    }
  }
  return (
    <Card
      className="panel-card"
      title={ru ? 'Интеграция с 3X-UI' : '3X-UI integration'}
    >
      <Typography.Paragraph type="secondary">
        {ru
          ? 'Связывает слушающие порты Xray, Sing-box и VPN-сервисов с названиями инбаундов, протоколом, транспортом и защитой из 3X-UI. Подключайте панель, управляющую этим сервером.'
          : 'Links Xray, Sing-box and VPN listener ports to inbound names, protocols, transports and security in 3X-UI. Connect the panel managing this server.'}
      </Typography.Paragraph>
      <Space style={{ marginBottom: 16 }}>
        <Switch
          checked={connection.enabled}
          onChange={(enabled) => setConnection((old) => ({ ...old, enabled }))}
        />
        <span>{ru ? 'Включить интеграцию' : 'Enable integration'}</span>
      </Space>
      <div className="settings-grid">
        <div>
          <label htmlFor="xui-url">
            {ru ? 'Адрес панели 3X-UI' : '3X-UI panel address'}
          </label>
          <Input
            id="xui-url"
            placeholder="https://panel.example.com/base-path"
            value={connection.url}
            onChange={(e) =>
              setConnection((old) => ({ ...old, url: e.target.value }))
            }
          />
          <Typography.Text type="secondary">
            {ru
              ? 'Включая секретный базовый путь панели. Для этого же сервера можно http://127.0.0.1:2053/путь.'
              : 'Include the panel base path. On the same server, a loopback HTTP URL can be used.'}
          </Typography.Text>
        </div>
        <div>
          <label htmlFor="xui-token">
            {ru ? 'API-токен 3X-UI (admin)' : '3X-UI API token (admin)'}
          </label>
          <Input.Password
            id="xui-token"
            autoComplete="new-password"
            value={token}
            placeholder={
              connection.tokenConfigured
                ? ru
                  ? 'Сохранён · пустое поле сохраняет токен'
                  : 'Saved · leave blank to keep'
                : ''
            }
            onChange={(e) => setToken(e.target.value)}
          />
          <Typography.Text type="secondary">
            {ru
              ? 'Создайте API-токен в настройках 3X-UI. Firewall-UI выполняет только запросы чтения; токен хранится на сервере и не возвращается в браузер.'
              : 'Create an API token in 3X-UI settings. Firewall-UI only reads metadata; the saved token is never sent back to the browser.'}
          </Typography.Text>
        </div>
      </div>
      {notice ? (
        <Alert
          style={{ marginTop: 16 }}
          type={notice.error ? 'error' : 'success'}
          showIcon
          title={notice.text}
        />
      ) : null}
      {connection.status?.message && !notice ? (
        <Alert
          style={{ marginTop: 16 }}
          type="warning"
          title={connection.status.message}
        />
      ) : null}
      <Space wrap style={{ marginTop: 16 }}>
        <Button
          type="primary"
          loading={busy === 'save'}
          disabled={!!busy && busy !== 'save'}
          onClick={() => void act('save')}
        >
          {ru ? 'Сохранить интеграцию' : 'Save integration'}
        </Button>
        <Button
          loading={busy === 'test'}
          disabled={!connection.url || !!busy}
          onClick={() => void act('test')}
        >
          {ru ? 'Проверить соединение' : 'Test connection'}
        </Button>
        {connection.tokenConfigured ? (
          <Button danger disabled={!!busy} onClick={() => void act('clear')}>
            {ru ? 'Отключить и удалить токен' : 'Disable and delete token'}
          </Button>
        ) : null}
      </Space>
    </Card>
  );
}
