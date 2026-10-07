import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Form,
  InputNumber,
  Select,
  Space,
  Spin,
  Switch,
  Typography,
  message,
} from 'antd';
import { SaveOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { HttpUtil } from '@/utils';

type RuntimeSettings = {
  listenHost: string;
  listenPort: number;
  externalPort: number;
  secureCookies: boolean;
  tlsEnabled: boolean;
};

type SaveSettingsResponse = RuntimeSettings & {
  restarting: boolean;
};

export default function SettingsPage() {
  const { i18n } = useTranslation();
  const ru = (i18n.resolvedLanguage || i18n.language || '').toLowerCase().startsWith('ru');
  const [form] = Form.useForm<RuntimeSettings>();
  const [current, setCurrent] = useState<RuntimeSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const text = useMemo(
    () =>
      ru
        ? {
            title: 'Веб-панель',
            hint: 'Настройки адреса и порта применяются перезапуском сервиса. Новый порт заранее добавляется в защитные правила Firewall-UI.',
            listen: 'Доступ к панели',
            local: 'Только localhost',
            ipv4: 'Все IPv4-интерфейсы',
            ipv6: 'Все IPv6-интерфейсы',
            port: 'Порт панели',
            external: 'Внешний порт reverse proxy',
            externalHint: '0 — не использовать отдельный внешний порт.',
            secure: 'Secure cookie',
            secureHint: 'Включайте при доступе к панели только через HTTPS.',
            tls: 'Встроенный TLS',
            tlsOn: 'Настроен',
            tlsOff: 'Не настроен',
            save: 'Сохранить и перезапустить',
            saved: 'Настройки сохранены. Firewall-UI перезапускается.',
            failed: 'Не удалось загрузить настройки панели.',
            reconnect: 'Если порт изменён при прямом доступе, браузер откроет новый адрес автоматически.',
          }
        : {
            title: 'Web panel',
            hint: 'Listen address and port changes are applied by restarting the service. Firewall-UI protects the new port before restart.',
            listen: 'Panel access',
            local: 'Localhost only',
            ipv4: 'All IPv4 interfaces',
            ipv6: 'All IPv6 interfaces',
            port: 'Panel port',
            external: 'Reverse proxy external port',
            externalHint: 'Use 0 when there is no separate public reverse-proxy port.',
            secure: 'Secure cookie',
            secureHint: 'Enable when the panel is accessed exclusively over HTTPS.',
            tls: 'Built-in TLS',
            tlsOn: 'Configured',
            tlsOff: 'Not configured',
            save: 'Save and restart',
            saved: 'Settings saved. Firewall-UI is restarting.',
            failed: 'Failed to load panel settings.',
            reconnect: 'When the direct-access port changes, the browser will open the new address automatically.',
          },
    [ru],
  );

  useEffect(() => {
    let cancelled = false;
    void HttpUtil.get<RuntimeSettings>('/api/settings')
      .then((result) => {
        if (cancelled) return;
        if (!result.success || !result.obj) {
          setError(result.msg || text.failed);
          return;
        }
        setCurrent(result.obj);
        form.setFieldsValue(result.obj);
      })
      .catch(() => {
        if (!cancelled) setError(text.failed);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [form, text.failed]);

  async function save(values: RuntimeSettings) {
    setSaving(true);
    setError('');
    try {
      const old = current;
      const result = await HttpUtil.post<SaveSettingsResponse>('/api/settings', values, {
        silentSuccess: true,
      });
      if (!result.success || !result.obj) {
        setError(result.msg || text.failed);
        return;
      }
      setCurrent(result.obj);
      void message.success(text.saved);

      const directPort = old?.listenPort;
      const browserPort = Number(window.location.port || (window.location.protocol === 'https:' ? 443 : 80));
      const shouldRedirect = directPort === browserPort && values.listenPort !== directPort;
      window.setTimeout(() => {
        if (shouldRedirect) {
          const target = new URL(window.location.href);
          target.port = String(values.listenPort);
          window.location.assign(target.toString());
        } else {
          window.location.reload();
        }
      }, 2200);
    } catch {
      setError(text.failed);
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="panel-card panel-loading">
        <Spin />
      </div>
    );
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      {error ? <Alert type="error" showIcon title={error} /> : null}
      <Card className="panel-card" title={text.title}>
        <Alert type="info" showIcon title={text.hint} description={text.reconnect} style={{ marginBottom: 20 }} />
        <Form<RuntimeSettings>
          form={form}
          layout="vertical"
          onFinish={(values) => void save(values)}
          initialValues={{
            listenHost: '127.0.0.1',
            listenPort: 8088,
            externalPort: 0,
            secureCookies: false,
          }}
        >
          <div className="settings-grid">
            <Form.Item name="listenHost" label={text.listen} rules={[{ required: true }]}>
              <Select
                options={[
                  { value: '127.0.0.1', label: text.local },
                  { value: '0.0.0.0', label: text.ipv4 },
                  { value: '::', label: text.ipv6 },
                ]}
              />
            </Form.Item>
            <Form.Item
              name="listenPort"
              label={text.port}
              rules={[{ required: true, type: 'number', min: 1, max: 65535 }]}
            >
              <InputNumber min={1} max={65535} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item
              name="externalPort"
              label={text.external}
              extra={text.externalHint}
              rules={[{ required: true, type: 'number', min: 0, max: 65535 }]}
            >
              <InputNumber min={0} max={65535} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="secureCookies" label={text.secure} valuePropName="checked" extra={text.secureHint}>
              <Switch />
            </Form.Item>
          </div>

          <div className="settings-status-row">
            <Typography.Text type="secondary">{text.tls}</Typography.Text>
            <Typography.Text strong>{current?.tlsEnabled ? text.tlsOn : text.tlsOff}</Typography.Text>
          </div>

          <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving}>
            {text.save}
          </Button>
        </Form>
      </Card>
    </Space>
  );
}
