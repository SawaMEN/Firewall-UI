import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Divider,
  Form,
  InputNumber,
  Popconfirm,
  Segmented,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Typography,
  message,
} from 'antd';
import { CloudDownloadOutlined, SaveOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { HttpUtil } from '@/utils';

type UpdateChannel = 'stable' | 'dev';

type RuntimeSettings = {
  listenHost: string;
  listenPort: number;
  externalPort: number;
  secureCookies: boolean;
  tlsEnabled: boolean;
  updateChannel: UpdateChannel;
  currentVersion: string;
  currentCommit: string;
  buildChannel: UpdateChannel | string;
};

type SaveSettingsResponse = RuntimeSettings & {
  restarting: boolean;
};

type UpdateManifest = {
  version: string;
  commit: string;
  channel: UpdateChannel;
};

type UpdateStatus = {
  current: UpdateManifest;
  channel: UpdateChannel;
  available?: UpdateManifest;
  updateAvailable: boolean;
  error?: string;
};

type StableUpdateResponse = {
  updated: boolean;
  version: string;
  commit: string;
  restarting: boolean;
};

export default function SettingsPage() {
  const { i18n } = useTranslation();
  const ru = (i18n.resolvedLanguage || i18n.language || '').toLowerCase().startsWith('ru');
  const [form] = Form.useForm<RuntimeSettings>();
  const selectedChannel = Form.useWatch('updateChannel', form) as UpdateChannel | undefined;
  const [current, setCurrent] = useState<RuntimeSettings | null>(null);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [updatingStable, setUpdatingStable] = useState(false);
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
            updates: 'Обновления',
            updateChannel: 'Канал обновлений',
            stable: 'Stable',
            dev: 'DEV',
            channelHint:
              'Stable обновляется только вручную. DEV автоматически устанавливает каждую новую успешную сборку main без подтверждений и уведомлений.',
            currentVersion: 'Текущая версия',
            latestVersion: 'Последняя версия',
            stableManual:
              'Стабильные релизы никогда не устанавливаются автоматически. Обновление выполняется только этой кнопкой после подтверждения.',
            devAuto:
              'DEV-режим полностью автоматический: после успешной сборки main новая версия публикуется и устанавливается в фоне. Сервис сам перезапустится.',
            stableUpdate: 'Обновить Stable',
            stableUpdateConfirm: 'Скачать, проверить и установить последний стабильный релиз?',
            stableUpdating: 'Установка стабильного обновления…',
            stableDone: 'Стабильное обновление установлено. Firewall-UI перезапускается.',
            stableCurrent: 'Уже установлена последняя стабильная версия.',
            updateCheckFailed: 'Не удалось проверить опубликованную версию.',
            saveChannelFirst: 'Смена канала вступает в силу после сохранения настроек.',
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
            updates: 'Updates',
            updateChannel: 'Update channel',
            stable: 'Stable',
            dev: 'DEV',
            channelHint:
              'Stable updates only on explicit confirmation. DEV automatically installs every new successful main build without confirmations or notifications.',
            currentVersion: 'Current version',
            latestVersion: 'Latest version',
            stableManual:
              'Stable releases are never installed automatically. Use this button and confirm when you want to update.',
            devAuto:
              'DEV is fully automatic: every successful main build is published and installed in the background. The service restarts itself.',
            stableUpdate: 'Update Stable',
            stableUpdateConfirm: 'Download, verify, and install the latest stable release?',
            stableUpdating: 'Installing stable update…',
            stableDone: 'Stable update installed. Firewall-UI is restarting.',
            stableCurrent: 'The latest stable version is already installed.',
            updateCheckFailed: 'Could not check the published version.',
            saveChannelFirst: 'A channel change takes effect after saving the settings.',
          },
    [ru],
  );

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const result = await HttpUtil.get<RuntimeSettings>('/api/settings');
        if (cancelled) return;
        if (!result.success || !result.obj) {
          setError(result.msg || text.failed);
          return;
        }
        setCurrent(result.obj);
        form.setFieldsValue(result.obj);

        try {
          const status = await HttpUtil.get<UpdateStatus>('/api/update/status');
          if (!cancelled && status.success && status.obj) {
            setUpdateStatus(status.obj);
          }
        } catch {
          // Update availability is optional; the rest of settings remains usable offline.
        }
      } catch {
        if (!cancelled) setError(text.failed);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();
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
    } catch {
      setError(text.failed);
    } finally {
      setSaving(false);
    }
  }

  async function installStable() {
    setUpdatingStable(true);
    try {
      const result = await HttpUtil.post<StableUpdateResponse>('/api/update/stable', undefined, {
        silentSuccess: true,
      });
      if (!result.success || !result.obj) {
        setError(result.msg || text.updateCheckFailed);
        return;
      }
      if (!result.obj.updated) {
        void message.info(text.stableCurrent);
        return;
      }
      void message.success(text.stableDone);
      window.setTimeout(() => window.location.reload(), 2500);
    } catch {
      setError(text.updateCheckFailed);
    } finally {
      setUpdatingStable(false);
    }
  }

  if (loading) {
    return (
      <div className="panel-card panel-loading">
        <Spin />
      </div>
    );
  }

  const savedChannel = current?.updateChannel || 'stable';
  const availableVersion = updateStatus?.available?.version;

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      {error ? <Alert type="error" showIcon title={error} /> : null}
      <Card className="panel-card" title={text.title}>
        <Alert
          type="info"
          showIcon
          title={text.hint}
          description={text.reconnect}
          style={{ marginBottom: 20 }}
        />
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

          <Divider titlePlacement="start">{text.updates}</Divider>

          <Form.Item name="updateChannel" label={text.updateChannel} extra={text.channelHint}>
            <Segmented
              block
              options={[
                { value: 'stable', label: text.stable },
                { value: 'dev', label: text.dev },
              ]}
            />
          </Form.Item>

          <Space direction="vertical" size="small" style={{ width: '100%', marginBottom: 20 }}>
            <Space wrap>
              <Typography.Text type="secondary">{text.currentVersion}:</Typography.Text>
              <Tag color={current?.buildChannel === 'dev' ? 'processing' : 'success'}>
                {current?.currentVersion || '—'}
              </Tag>
              {current?.currentCommit ? (
                <Typography.Text code>
                  {current.currentCommit.slice(0, 12)}
                </Typography.Text>
              ) : null}
            </Space>

            {availableVersion ? (
              <Space wrap>
                <Typography.Text type="secondary">{text.latestVersion}:</Typography.Text>
                <Tag>{availableVersion}</Tag>
                {updateStatus?.updateAvailable ? <Tag color="warning">new</Tag> : null}
              </Space>
            ) : updateStatus?.error ? (
              <Typography.Text type="secondary">{text.updateCheckFailed}</Typography.Text>
            ) : null}

            {savedChannel === 'dev' ? (
              <Alert type="info" showIcon title="DEV" description={text.devAuto} />
            ) : (
              <Alert
                type="success"
                showIcon
                title={text.stable}
                description={
                  <Space direction="vertical" size="small">
                    <Typography.Text>{text.stableManual}</Typography.Text>
                    <Popconfirm
                      title={text.stableUpdateConfirm}
                      okText={text.stableUpdate}
                      cancelText={ru ? 'Отмена' : 'Cancel'}
                      onConfirm={() => void installStable()}
                    >
                      <Button
                        icon={<CloudDownloadOutlined />}
                        loading={updatingStable}
                        disabled={updatingStable}
                      >
                        {updatingStable ? text.stableUpdating : text.stableUpdate}
                      </Button>
                    </Popconfirm>
                  </Space>
                }
              />
            )}

            {selectedChannel && selectedChannel !== savedChannel ? (
              <Typography.Text type="warning">{text.saveChannelFirst}</Typography.Text>
            ) : null}
          </Space>

          <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving}>
            {text.save}
          </Button>
        </Form>
      </Card>
    </Space>
  );
}
