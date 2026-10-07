import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Form,
  InputNumber,
  Popconfirm,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Typography,
  message,
} from 'antd';
import { ReloadOutlined, SaveOutlined, SyncOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { HttpUtil } from '@/utils';

type RuntimeSettings = {
  listenHost: string;
  listenPort: number;
  externalPort: number;
  secureCookies: boolean;
  tlsEnabled: boolean;
  updateChannel: 'stable' | 'dev';
};

type SaveSettingsResponse = RuntimeSettings & {
  restarting: boolean;
};

type UpdateStatus = {
  currentVersion: string;
  currentChannel: string;
  currentCommit: string;
  selectedChannel: 'stable' | 'dev';
  latestVersion: string;
  latestCommit: string;
  available: boolean;
  restarting?: boolean;
};

export default function SettingsPage() {
  const { i18n } = useTranslation();
  const ru = (i18n.resolvedLanguage || i18n.language || '').toLowerCase().startsWith('ru');
  const [form] = Form.useForm<RuntimeSettings>();
  const [current, setCurrent] = useState<RuntimeSettings | null>(null);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [applyingUpdate, setApplyingUpdate] = useState(false);
  const [error, setError] = useState('');
  const [updateError, setUpdateError] = useState('');

  const text = useMemo(
    () =>
      ru
        ? {
            webTitle: 'Веб-панель',
            hint: 'Изменения адреса и порта применяются безопасным перезапуском сервиса. Новый порт заранее добавляется в защитные правила Firewall-UI.',
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
            save: 'Сохранить настройки',
            saved: 'Настройки сохранены.',
            restarting: 'Настройки сохранены. Firewall-UI перезапускается.',
            failed: 'Не удалось загрузить настройки панели.',
            reconnect: 'Если порт изменён при прямом доступе, браузер откроет новый адрес автоматически.',
            updates: 'Обновления',
            channel: 'Канал обновлений',
            stable: 'Stable',
            dev: 'Dev',
            stableHint: 'Стабильные релизы не устанавливаются автоматически. Проверка и установка выполняются кнопкой ниже с подтверждением.',
            devHint: 'Dev-сборки публикуются из main автоматически и устанавливаются сервером без подтверждений и уведомлений.',
            current: 'Текущая версия',
            latest: 'Доступная версия',
            noUpdate: 'Установлена актуальная версия.',
            check: 'Проверить обновление',
            update: 'Обновить до',
            updateConfirm: 'Установить стабильное обновление и перезапустить Firewall-UI?',
            updateNow: 'Обновить',
            updateApplied: 'Обновление установлено. Firewall-UI перезапускается.',
            updateFailed: 'Не удалось проверить или установить обновление.',
            devActive: 'Автообновление Dev активно',
          }
        : {
            webTitle: 'Web panel',
            hint: 'Listen address and port changes are applied with a safe service restart. Firewall-UI protects the new port before restarting.',
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
            save: 'Save settings',
            saved: 'Settings saved.',
            restarting: 'Settings saved. Firewall-UI is restarting.',
            failed: 'Failed to load panel settings.',
            reconnect: 'When the direct-access port changes, the browser will open the new address automatically.',
            updates: 'Updates',
            channel: 'Update channel',
            stable: 'Stable',
            dev: 'Dev',
            stableHint: 'Stable releases are never installed automatically. Check and install them with the button below and an explicit confirmation.',
            devHint: 'Dev builds are published from main automatically and installed by the server without confirmations or notifications.',
            current: 'Current version',
            latest: 'Available version',
            noUpdate: 'The current version is up to date.',
            check: 'Check for update',
            update: 'Update to',
            updateConfirm: 'Install the stable update and restart Firewall-UI?',
            updateNow: 'Update',
            updateApplied: 'Update installed. Firewall-UI is restarting.',
            updateFailed: 'Failed to check or install the update.',
            devActive: 'Dev auto-update is active',
          },
    [ru],
  );

  async function loadUpdateStatus() {
    setCheckingUpdate(true);
    setUpdateError('');
    try {
      const result = await HttpUtil.get<UpdateStatus>('/api/update/status');
      if (result.success && result.obj) {
        setUpdateStatus(result.obj);
      } else {
        setUpdateError(result.msg || text.updateFailed);
      }
    } catch {
      setUpdateError(text.updateFailed);
    } finally {
      setCheckingUpdate(false);
    }
  }

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
        void loadUpdateStatus();
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
      form.setFieldsValue(result.obj);
      if (result.obj.restarting) {
        void message.success(text.restarting);
        const directPort = old?.listenPort;
        const browserPort = Number(
          window.location.port || (window.location.protocol === 'https:' ? 443 : 80),
        );
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
      } else {
        void message.success(text.saved);
        void loadUpdateStatus();
      }
    } catch {
      setError(text.failed);
    } finally {
      setSaving(false);
    }
  }

  async function applyStableUpdate() {
    setApplyingUpdate(true);
    setUpdateError('');
    try {
      const result = await HttpUtil.post<UpdateStatus>('/api/update/apply', {}, {
        silentSuccess: true,
      });
      if (!result.success || !result.obj) {
        setUpdateError(result.msg || text.updateFailed);
        return;
      }
      setUpdateStatus(result.obj);
      if (result.obj.restarting) {
        void message.success(text.updateApplied);
        window.setTimeout(() => window.location.reload(), 2600);
      }
    } catch {
      setUpdateError(text.updateFailed);
    } finally {
      setApplyingUpdate(false);
    }
  }

  if (loading) {
    return (
      <div className="panel-card panel-loading">
        <Spin />
      </div>
    );
  }

  const persistedChannel = current?.updateChannel || 'stable';

  return (
    <Form<RuntimeSettings>
      form={form}
      layout="vertical"
      onFinish={(values) => void save(values)}
      initialValues={{
        listenHost: '127.0.0.1',
        listenPort: 8088,
        externalPort: 0,
        secureCookies: false,
        updateChannel: 'stable',
      }}
    >
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        {error ? <Alert type="error" showIcon title={error} /> : null}

        <Card className="panel-card" title={text.webTitle}>
          <Alert
            type="info"
            showIcon
            title={text.hint}
            description={text.reconnect}
            style={{ marginBottom: 20 }}
          />
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
            <Form.Item
              name="secureCookies"
              label={text.secure}
              valuePropName="checked"
              extra={text.secureHint}
            >
              <Switch />
            </Form.Item>
          </div>

          <div className="settings-status-row">
            <Typography.Text type="secondary">{text.tls}</Typography.Text>
            <Typography.Text strong>{current?.tlsEnabled ? text.tlsOn : text.tlsOff}</Typography.Text>
          </div>
        </Card>

        <Card className="panel-card" title={text.updates}>
          <Form.Item name="updateChannel" label={text.channel} style={{ marginBottom: 12 }}>
            <Select
              style={{ maxWidth: 320 }}
              options={[
                { value: 'stable', label: text.stable },
                { value: 'dev', label: text.dev },
              ]}
            />
          </Form.Item>

          <Alert
            type={persistedChannel === 'dev' ? 'warning' : 'info'}
            showIcon
            title={persistedChannel === 'dev' ? text.devActive : text.stable}
            description={persistedChannel === 'dev' ? text.devHint : text.stableHint}
            style={{ marginBottom: 18 }}
          />

          {updateError ? (
            <Alert type="error" showIcon title={updateError} style={{ marginBottom: 18 }} />
          ) : null}

          <Space direction="vertical" size="small" style={{ width: '100%' }}>
            <Space wrap>
              <Typography.Text type="secondary">{text.current}:</Typography.Text>
              <Tag>{updateStatus?.currentVersion || '—'}</Tag>
              {updateStatus?.currentChannel ? <Tag>{updateStatus.currentChannel}</Tag> : null}
            </Space>
            <Space wrap>
              <Typography.Text type="secondary">{text.latest}:</Typography.Text>
              <Tag color={updateStatus?.available ? 'processing' : undefined}>
                {updateStatus?.latestVersion || '—'}
              </Tag>
            </Space>

            {persistedChannel === 'stable' ? (
              <Space wrap style={{ marginTop: 8 }}>
                <Button
                  icon={<ReloadOutlined />}
                  loading={checkingUpdate}
                  onClick={() => void loadUpdateStatus()}
                >
                  {text.check}
                </Button>
                {updateStatus?.available ? (
                  <Popconfirm
                    title={text.updateConfirm}
                    okText={text.updateNow}
                    cancelText={ru ? 'Отмена' : 'Cancel'}
                    onConfirm={() => void applyStableUpdate()}
                  >
                    <Button
                      type="primary"
                      icon={<SyncOutlined />}
                      loading={applyingUpdate}
                    >
                      {text.update} {updateStatus.latestVersion}
                    </Button>
                  </Popconfirm>
                ) : updateStatus ? (
                  <Typography.Text type="secondary">{text.noUpdate}</Typography.Text>
                ) : null}
              </Space>
            ) : null}
          </Space>
        </Card>

        <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving}>
          {text.save}
        </Button>
      </Space>
    </Form>
  );
}
