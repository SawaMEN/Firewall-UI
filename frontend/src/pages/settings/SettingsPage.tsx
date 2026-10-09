import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Divider,
  Form,
  Input,
  InputNumber,
  message,
  Popconfirm,
  Select,
  Space,
  Spin,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd';
import {
  DownloadOutlined,
  HistoryOutlined,
  ReloadOutlined,
  SaveOutlined,
  SyncOutlined,
  UploadOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';

import { HttpUtil } from '@/utils';

type RuntimeSettings = {
  publicHost: string;
  listenHost: string;
  listenPort: number;
  externalPort: number;
  secureCookies: boolean;
  tlsEnabled: boolean;
  tlsCert: string;
  tlsKey: string;
  updateChannel: string;
  allowedCidrs: string[];
  totpEnabled: boolean;
  rollbackSeconds: number;
  portScanInterval: number;
  restarting?: boolean;
};

type FormSettings = Omit<RuntimeSettings, 'allowedCidrs' | 'totpEnabled' | 'tlsEnabled' | 'restarting'> & {
  allowedCidrsText: string;
};

type UpdateStatus = {
  currentVersion: string;
  currentChannel: string;
  latestVersion: string;
  available: boolean;
  restarting?: boolean;
};

type TOTPSetup = { secret: string; uri: string };
type AuditEntry = {
  time: string;
  user?: string;
  remoteIp?: string;
  action: string;
  success: boolean;
  message?: string;
};
type HistorySnapshot = { id: string; createdAt: string; reason: string };
type BackupRestoreResult = {
  restored: boolean;
  restartRequired?: boolean;
  rollback?: { token: string; deadline: string };
};

export default function SettingsPage() {
  const { i18n } = useTranslation();
  const ru = i18n.language.startsWith('ru');
  const [form] = Form.useForm<FormSettings>();
  const restoreInput = useRef<HTMLInputElement>(null);
  const [current, setCurrent] = useState<RuntimeSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [applyingUpdate, setApplyingUpdate] = useState(false);
  const [updateError, setUpdateError] = useState('');
  const [totpSetup, setTotpSetup] = useState<TOTPSetup | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [credentials, setCredentials] = useState({ username: '', password: '', currentPassword: '', code: '' });
  const [credentialsBusy, setCredentialsBusy] = useState(false);
  const [credentialError, setCredentialError] = useState('');
  const [securityBusy, setSecurityBusy] = useState(false);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [history, setHistory] = useState<HistorySnapshot[]>([]);
  const [historyBusy, setHistoryBusy] = useState('');
  const [restartRequired, setRestartRequired] = useState(false);

  const text = useMemo(
    () =>
      ru
        ? {
            webTitle: 'Веб-панель и безопасность',
            hint: 'Рекомендуется localhost + reverse proxy/SSH tunnel. CIDR allowlist нельзя сохранить, если он отрежет текущего клиента.',
            listen: 'Доступ к панели',
            local: 'Только localhost',
            ipv4: 'Все IPv4-интерфейсы',
            ipv6: 'Все IPv6-интерфейсы',
            port: 'Порт панели',
            external: 'Внешний порт reverse proxy',
            externalHint: '0 — отдельного внешнего порта нет.',
            secure: 'Secure cookie',
            secureHint: 'Включайте при доступе только через HTTPS.',
            cidrs: 'Разрешённые IP/CIDR',
            cidrsHint: 'По одному IP или CIDR на строку. Пусто — ограничение отключено.',
            rollback: 'Rollback timeout, сек.',
            rollbackHint: 'UI должен подтвердить доступность после опасного изменения, иначе прошлые правила восстановятся.',
            scan: 'Интервал сканирования портов, сек.',
            tls: 'Встроенный TLS',
            tlsOn: 'Настроен',
            tlsOff: 'Не настроен',
            save: 'Сохранить настройки',
            restarting: 'Настройки сохранены. Firewall-UI перезапускается.',
            failed: 'Не удалось загрузить настройки.',
            twoFactor: 'Двухфакторная аутентификация (TOTP)',
            twoFactorOn: 'TOTP включён',
            twoFactorOff: 'TOTP выключен',
            setup2fa: 'Настроить TOTP',
            enable2fa: 'Подтвердить и включить',
            disable2fa: 'Отключить TOTP',
            secret: 'Секрет',
            uri: 'otpauth URI',
            code: '6-значный код',
            updates: 'Обновления',
            channel: 'Канал обновлений',
            stable: 'Stable',
            dev: 'Dev',
            stableHint: 'Stable устанавливается вручную после проверки SHA-256.',
            devHint: 'Dev обновляется автоматически из main.',
            current: 'Текущая версия',
            latest: 'Доступная версия',
            check: 'Проверить',
            update: 'Установить',
            updateConfirm: 'Установить stable-обновление и перезапустить Firewall-UI?',
            noUpdate: 'Установлена актуальная версия.',
            backup: 'Backup и история',
            export: 'Скачать backup',
            import: 'Восстановить backup',
            restoreConfirm: 'Восстановить этот снимок правил?',
            historyEmpty: 'История пока пуста',
            restart: 'Перезапустить сервис',
            restartNeeded: 'Backup восстановлен. Для применения сетевых настроек нужен перезапуск.',
            audit: 'Журнал действий',
            time: 'Время',
            action: 'Действие',
            result: 'Результат',
            client: 'Клиент',
          }
        : {
            webTitle: 'Web panel & security',
            hint: 'Localhost with a reverse proxy/SSH tunnel is recommended. The CIDR allowlist cannot be saved if it would lock out the current client.',
            listen: 'Panel access',
            local: 'Localhost only',
            ipv4: 'All IPv4 interfaces',
            ipv6: 'All IPv6 interfaces',
            port: 'Panel port',
            external: 'Reverse proxy external port',
            externalHint: 'Use 0 when there is no separate public port.',
            secure: 'Secure cookie',
            secureHint: 'Enable when the panel is accessed exclusively over HTTPS.',
            cidrs: 'Allowed IP/CIDR',
            cidrsHint: 'One IP or CIDR per line. Empty means unrestricted.',
            rollback: 'Rollback timeout, sec.',
            rollbackHint: 'The UI must confirm connectivity after risky changes or previous rules are restored.',
            scan: 'Port scan interval, sec.',
            tls: 'Built-in TLS',
            tlsOn: 'Configured',
            tlsOff: 'Not configured',
            save: 'Save settings',
            restarting: 'Settings saved. Firewall-UI is restarting.',
            failed: 'Failed to load settings.',
            twoFactor: 'Two-factor authentication (TOTP)',
            twoFactorOn: 'TOTP enabled',
            twoFactorOff: 'TOTP disabled',
            setup2fa: 'Set up TOTP',
            enable2fa: 'Verify and enable',
            disable2fa: 'Disable TOTP',
            secret: 'Secret',
            uri: 'otpauth URI',
            code: '6-digit code',
            updates: 'Updates',
            channel: 'Update channel',
            stable: 'Stable',
            dev: 'Dev',
            stableHint: 'Stable is installed manually after SHA-256 verification.',
            devHint: 'Dev updates automatically from main.',
            current: 'Current version',
            latest: 'Available version',
            check: 'Check',
            update: 'Install',
            updateConfirm: 'Install the stable update and restart Firewall-UI?',
            noUpdate: 'The current version is up to date.',
            backup: 'Backup & history',
            export: 'Download backup',
            import: 'Restore backup',
            restoreConfirm: 'Restore this rules snapshot?',
            historyEmpty: 'No history yet',
            restart: 'Restart service',
            restartNeeded: 'Backup restored. A restart is required to apply network settings.',
            audit: 'Audit log',
            time: 'Time',
            action: 'Action',
            result: 'Result',
            client: 'Client',
          },
    [ru],
  );

  async function loadUpdateStatus() {
    setCheckingUpdate(true);
    setUpdateError('');
    try {
      const result = await HttpUtil.get<UpdateStatus>('/api/update/status');
      if (result.success && result.obj) setUpdateStatus(result.obj);
      else setUpdateError(result.msg);
    } finally {
      setCheckingUpdate(false);
    }
  }

  async function loadActivity() {
    const [auditResult, historyResult] = await Promise.all([
      HttpUtil.get<AuditEntry[]>('/api/audit'),
      HttpUtil.get<HistorySnapshot[]>('/api/history'),
    ]);
    if (auditResult.success && auditResult.obj) setAudit(auditResult.obj);
    if (historyResult.success && historyResult.obj) setHistory(historyResult.obj);
  }

  useEffect(() => {
    let cancelled = false;
    void HttpUtil.get<{ username: string }>('/api/session').then((result) => {
      if (!cancelled && result.success && result.obj) setCredentials((old) => ({ ...old, username: result.obj!.username }));
    });
    void HttpUtil.get<RuntimeSettings>('/api/settings')
      .then((result) => {
        if (cancelled) return;
        if (!result.success || !result.obj) {
          setError(result.msg || text.failed);
          return;
        }
        setCurrent(result.obj);
        form.setFieldsValue({
          publicHost: result.obj.publicHost,
          tlsCert: result.obj.tlsCert,
          tlsKey: result.obj.tlsKey,
          listenHost: result.obj.listenHost,
          listenPort: result.obj.listenPort,
          externalPort: result.obj.externalPort,
          secureCookies: result.obj.secureCookies,
          updateChannel: result.obj.updateChannel,
          rollbackSeconds: result.obj.rollbackSeconds,
          portScanInterval: result.obj.portScanInterval,
          allowedCidrsText: (result.obj.allowedCidrs || []).join('\n'),
        });
        void loadUpdateStatus();
        void loadActivity();
      })
      .catch(() => !cancelled && setError(text.failed))
      .finally(() => !cancelled && setLoading(false));
    return () => { cancelled = true; };
  }, [form, text.failed]);

  async function save(values: FormSettings) {
    setSaving(true);
    try {
      const old = current;
      const allowedCidrs = values.allowedCidrsText
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);
      const result = await HttpUtil.post<RuntimeSettings>('/api/settings', {
        publicHost: values.publicHost || '',
        listenHost: values.listenHost,
        listenPort: values.listenPort,
        externalPort: values.externalPort,
        secureCookies: values.secureCookies,
        tlsCert: values.tlsCert || '',
        tlsKey: values.tlsKey || '',
        updateChannel: values.updateChannel,
        allowedCidrs,
        rollbackSeconds: values.rollbackSeconds,
        portScanInterval: values.portScanInterval,
      });
      if (!result.success || !result.obj) {
        setError(result.msg || text.failed);
        return;
      }
      setCurrent(result.obj);
      if (result.obj.restarting) {
        void message.success(text.restarting);
        const browserPort = Number(window.location.port || (window.location.protocol === 'https:' ? 443 : 80));
        const direct = old?.listenPort === browserPort;
        window.setTimeout(() => {
          if (direct && (old?.listenPort !== values.listenPort || old?.tlsEnabled !== Boolean(values.tlsCert))) {
            const target = new URL(window.location.href);
            if (values.publicHost) target.hostname = values.publicHost.includes(':') ? `[${values.publicHost}]` : values.publicHost;
            target.port = String(values.listenPort);
            target.protocol = values.tlsCert ? 'https:' : 'http:';
            window.location.assign(target.toString());
          } else {
            window.location.reload();
          }
        }, 2200);
      } else {
        void message.success(ru ? 'Настройки сохранены' : 'Settings saved');
      }
    } finally {
      setSaving(false);
    }
  }

  async function changeCredentials() {
    setCredentialsBusy(true);
    setCredentialError('');
    try {
      const result = await HttpUtil.post('/api/security/credentials', credentials, { silentSuccess: true });
      if (result.success) {
        setCredentials({ username: '', password: '', currentPassword: '', code: '' });
        void message.success(ru ? 'Логин и пароль изменены. Войдите заново.' : 'Credentials changed. Please sign in again.');
        window.dispatchEvent(new Event('session-expired'));
      } else setCredentialError(result.msg);
    } finally { setCredentialsBusy(false); }
  }

  async function setupTOTP() {
    setSecurityBusy(true);
    try {
      const result = await HttpUtil.post<TOTPSetup>('/api/security/totp/setup', {});
      if (result.success && result.obj) setTotpSetup(result.obj);
    } finally { setSecurityBusy(false); }
  }

  async function confirmTOTP() {
    setSecurityBusy(true);
    try {
      const result = await HttpUtil.post<{ enabled: boolean }>('/api/security/totp/confirm', { code: totpCode });
      if (result.success && result.obj?.enabled) {
        setCurrent((old) => old ? { ...old, totpEnabled: true } : old);
        setTotpSetup(null);
        setTotpCode('');
      }
    } finally { setSecurityBusy(false); }
  }

  async function disableTOTP() {
    setSecurityBusy(true);
    try {
      const result = await HttpUtil.post<{ enabled: boolean }>('/api/security/totp/disable', { code: totpCode });
      if (result.success) {
        setCurrent((old) => old ? { ...old, totpEnabled: false } : old);
        setTotpCode('');
      }
    } finally { setSecurityBusy(false); }
  }

  async function applyStableUpdate() {
    setApplyingUpdate(true);
    try {
      const result = await HttpUtil.post<UpdateStatus>('/api/update/apply', {});
      if (result.success && result.obj) {
        setUpdateStatus(result.obj);
        if (result.obj.restarting) window.setTimeout(() => window.location.reload(), 2600);
      }
    } finally { setApplyingUpdate(false); }
  }

  async function downloadBackup() {
    const result = await HttpUtil.get<Record<string, unknown>>('/api/backup');
    if (!result.success || !result.obj) return;
    const blob = new Blob([JSON.stringify(result.obj, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'firewall-ui-backup-' + new Date().toISOString().replace(/[:.]/g, '-') + '.json';
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function restoreBackupFile(file: File) {
    try {
      const parsed = JSON.parse(await file.text()) as Record<string, unknown>;
      const result = await HttpUtil.post<BackupRestoreResult>('/api/backup/restore', parsed);
      if (result.success && result.obj) {
        setRestartRequired(Boolean(result.obj.restartRequired));
        void loadActivity();
        void message.success(ru ? 'Backup восстановлен' : 'Backup restored');
      }
    } catch {
      void message.error(ru ? 'Некорректный backup JSON' : 'Invalid backup JSON');
    } finally {
      if (restoreInput.current) restoreInput.current.value = '';
    }
  }

  async function restoreHistory(id: string) {
    setHistoryBusy(id);
    try {
      const result = await HttpUtil.post('/api/history/restore', { id });
      if (result.success) {
        void loadActivity();
        void message.success(ru ? 'Снимок восстановлен' : 'Snapshot restored');
      }
    } finally { setHistoryBusy(''); }
  }

  async function restart() {
    const result = await HttpUtil.post<{ restarting: boolean }>('/api/system/restart', {});
    if (result.success) window.setTimeout(() => window.location.reload(), 2200);
  }

  if (loading) return <div className="panel-card panel-loading"><Spin /></div>;
  const channel = current?.updateChannel || 'stable';

  return (
    <Form<FormSettings>
      form={form}
      layout="vertical"
      onFinish={(values) => void save(values)}
      initialValues={{
        listenHost: '127.0.0.1',
        listenPort: 8088,
        externalPort: 0,
        secureCookies: false,
        updateChannel: 'stable',
        rollbackSeconds: 45,
        portScanInterval: 2,
        allowedCidrsText: '',
      }}
    >
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        {error ? <Alert type="error" showIcon title={error} /> : null}

        <Card className="panel-card" title={ru ? 'Логин и пароль' : 'Username and password'}>
          <Typography.Paragraph type="secondary">
            {ru ? 'Пароль может быть любой длины. Рекомендуем длинный уникальный пароль и 2FA. После изменения потребуется повторный вход на всех устройствах.' : 'Any nonempty password is accepted. We recommend a long unique password and 2FA. All devices will need to sign in again.'}
          </Typography.Paragraph>
          {credentialError ? <Alert type="error" showIcon title={credentialError} style={{ marginBottom: 16 }} /> : null}
          <div className="settings-grid">
            <div><Typography.Text>{ru ? 'Новый логин' : 'New username'}</Typography.Text><Input autoComplete="username" value={credentials.username} onChange={(event) => setCredentials((old) => ({ ...old, username: event.target.value }))} /></div>
            <div><Typography.Text>{ru ? 'Новый пароль' : 'New password'}</Typography.Text><Input.Password autoComplete="new-password" value={credentials.password} onChange={(event) => setCredentials((old) => ({ ...old, password: event.target.value }))} /></div>
            <div><Typography.Text>{ru ? 'Текущий пароль' : 'Current password'}</Typography.Text><Input.Password autoComplete="current-password" value={credentials.currentPassword} onChange={(event) => setCredentials((old) => ({ ...old, currentPassword: event.target.value }))} /></div>
            {current?.totpEnabled ? <div><Typography.Text>{ru ? 'Код 2FA' : '2FA code'}</Typography.Text><Input inputMode="numeric" maxLength={6} value={credentials.code} onChange={(event) => setCredentials((old) => ({ ...old, code: event.target.value.replace(/\D/g, '').slice(0, 6) }))} /></div> : null}
          </div>
          <Button style={{ marginTop: 16 }} type="primary" loading={credentialsBusy} disabled={!credentials.username.trim() || !credentials.password || !credentials.currentPassword || (current?.totpEnabled && credentials.code.length !== 6)} onClick={() => void changeCredentials()}>
            {ru ? 'Изменить логин и пароль' : 'Change username and password'}
          </Button>
        </Card>

        <Card className="panel-card" title={text.webTitle}>
          <Alert type="info" showIcon title={text.hint} style={{ marginBottom: 20 }} />
          <div className="settings-grid">
            <Form.Item name="listenHost" label={text.listen}>
              <Select options={[
                { value: '127.0.0.1', label: text.local },
                { value: '0.0.0.0', label: text.ipv4 },
                { value: '::', label: text.ipv6 },
              ]} />
            </Form.Item>
            <Form.Item name="publicHost" label={ru ? 'Домен или IP для внешнего доступа' : 'External domain or IP'} extra={ru ? 'Без https:// и порта. Сертификат должен быть выдан для этого адреса.' : 'Without scheme or port. The certificate must cover this address.'}>
              <Input placeholder="panel.example.com / 203.0.113.10" />
            </Form.Item>
            <Form.Item name="listenPort" label={text.port}>
              <InputNumber min={1} max={65535} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="externalPort" label={text.external} extra={text.externalHint}>
              <InputNumber min={0} max={65535} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="secureCookies" label={text.secure} valuePropName="checked" extra={text.secureHint}>
              <Switch />
            </Form.Item>
            <Form.Item name="rollbackSeconds" label={text.rollback} extra={text.rollbackHint}>
              <InputNumber min={15} max={300} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item name="portScanInterval" label={text.scan}>
              <InputNumber min={1} max={30} style={{ width: '100%' }} />
            </Form.Item>
          </div>
          <Form.Item name="allowedCidrsText" label={text.cidrs} extra={text.cidrsHint}>
            <Input.TextArea rows={4} placeholder={'192.0.2.10\n10.0.0.0/8\n2001:db8::/32'} />
          </Form.Item>
          <div className="settings-grid">
            <Form.Item name="tlsCert" label={ru ? 'HTTPS: файл сертификата PEM' : 'HTTPS: PEM certificate path'} extra={ru ? 'Абсолютный путь на сервере. Оба поля пустые — HTTP.' : 'Absolute server path. Leave both fields empty for HTTP.'}>
              <Input placeholder="/etc/letsencrypt/live/example.com/fullchain.pem" />
            </Form.Item>
            <Form.Item name="tlsKey" label={ru ? 'HTTPS: файл приватного ключа PEM' : 'HTTPS: PEM private key path'}>
              <Input placeholder="/etc/letsencrypt/live/example.com/privkey.pem" />
            </Form.Item>
          </div>
          {current?.publicHost ? <Typography.Paragraph>
            {ru ? 'Адрес панели: ' : 'Panel URL: '}
            <Typography.Text copyable>{`${current.tlsEnabled ? 'https' : 'http'}://${current.publicHost.includes(':') ? `[${current.publicHost}]` : current.publicHost}:${current.externalPort || current.listenPort}/`}</Typography.Text>
          </Typography.Paragraph> : null}
          <Space>
            <Typography.Text type="secondary">{text.tls}:</Typography.Text>
            <Tag color={current?.tlsEnabled ? 'success' : undefined}>{current?.tlsEnabled ? text.tlsOn : text.tlsOff}</Tag>
          </Space>

          <Divider />
          <Typography.Title level={5}>{text.twoFactor}</Typography.Title>
          <Space direction="vertical" size="small" style={{ width: '100%' }}>
            <Tag color={current?.totpEnabled ? 'success' : undefined}>
              {current?.totpEnabled ? text.twoFactorOn : text.twoFactorOff}
            </Tag>
            {!current?.totpEnabled && !totpSetup ? (
              <Button loading={securityBusy} onClick={() => void setupTOTP()}>{text.setup2fa}</Button>
            ) : null}
            {totpSetup ? (
              <Card size="small">
                <Space direction="vertical" style={{ width: '100%' }}>
                  <Typography.Text strong>{text.secret}</Typography.Text>
                  <Typography.Text code copyable>{totpSetup.secret}</Typography.Text>
                  <Typography.Text strong>{text.uri}</Typography.Text>
                  <Typography.Text code copyable>{totpSetup.uri}</Typography.Text>
                </Space>
              </Card>
            ) : null}
            {(totpSetup || current?.totpEnabled) ? (
              <Space wrap>
                <Input
                  value={totpCode}
                  onChange={(event) => setTotpCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
                  inputMode="numeric"
                  maxLength={6}
                  placeholder={text.code}
                  style={{ width: 180 }}
                />
                {totpSetup ? (
                  <Button type="primary" disabled={totpCode.length !== 6} loading={securityBusy} onClick={() => void confirmTOTP()}>
                    {text.enable2fa}
                  </Button>
                ) : (
                  <Popconfirm title={text.disable2fa} onConfirm={() => void disableTOTP()}>
                    <Button danger disabled={totpCode.length !== 6} loading={securityBusy}>{text.disable2fa}</Button>
                  </Popconfirm>
                )}
              </Space>
            ) : null}
          </Space>
        </Card>

        <Card className="panel-card" title={text.updates}>
          <Form.Item name="updateChannel" label={text.channel}>
            <Select style={{ maxWidth: 320 }} options={[
              { value: 'stable', label: text.stable },
              { value: 'dev', label: text.dev },
            ]} />
          </Form.Item>
          <Alert type={channel === 'dev' ? 'warning' : 'info'} showIcon title={channel === 'dev' ? text.dev : text.stable} description={channel === 'dev' ? text.devHint : text.stableHint} style={{ marginBottom: 16 }} />
          {updateError ? <Alert type="error" showIcon title={updateError} style={{ marginBottom: 16 }} /> : null}
          <Space wrap>
            <Typography.Text>{text.current}: <Tag>{updateStatus?.currentVersion || '—'}</Tag></Typography.Text>
            <Typography.Text>{text.latest}: <Tag color={updateStatus?.available ? 'processing' : undefined}>{updateStatus?.latestVersion || '—'}</Tag></Typography.Text>
            <Button icon={<ReloadOutlined />} loading={checkingUpdate} onClick={() => void loadUpdateStatus()}>{text.check}</Button>
            {channel === 'stable' && updateStatus?.available ? (
              <Popconfirm title={text.updateConfirm} onConfirm={() => void applyStableUpdate()}>
                <Button type="primary" icon={<SyncOutlined />} loading={applyingUpdate}>{text.update}</Button>
              </Popconfirm>
            ) : updateStatus && !updateStatus.available ? <Typography.Text type="secondary">{text.noUpdate}</Typography.Text> : null}
          </Space>
        </Card>

        <Card className="panel-card" title={text.backup}>
          {restartRequired ? (
            <Alert
              type="warning"
              showIcon
              title={text.restartNeeded}
              action={<Button onClick={() => void restart()}>{text.restart}</Button>}
              style={{ marginBottom: 16 }}
            />
          ) : null}
          <Space wrap style={{ marginBottom: 16 }}>
            <Button icon={<DownloadOutlined />} onClick={() => void downloadBackup()}>{text.export}</Button>
            <Button icon={<UploadOutlined />} onClick={() => restoreInput.current?.click()}>{text.import}</Button>
            <input
              ref={restoreInput}
              type="file"
              accept="application/json,.json"
              hidden
              onChange={(event) => {
                const file = event.target.files?.[0];
                if (file) void restoreBackupFile(file);
              }}
            />
            <Button icon={<HistoryOutlined />} onClick={() => void loadActivity()}>{ru ? 'Обновить историю' : 'Refresh history'}</Button>
          </Space>
          <Table<HistorySnapshot>
            size="small"
            rowKey="id"
            dataSource={history}
            pagination={{ pageSize: 8, hideOnSinglePage: true }}
            locale={{ emptyText: text.historyEmpty }}
            columns={[
              { title: text.time, dataIndex: 'createdAt', width: 190, render: (value: string) => new Date(value).toLocaleString() },
              { title: text.action, dataIndex: 'reason' },
              {
                title: '',
                width: 120,
                render: (_, row) => (
                  <Popconfirm title={text.restoreConfirm} onConfirm={() => void restoreHistory(row.id)}>
                    <Button size="small" loading={historyBusy === row.id}>{ru ? 'Восстановить' : 'Restore'}</Button>
                  </Popconfirm>
                ),
              },
            ]}
          />
        </Card>

        <Card className="panel-card" title={text.audit}>
          <Table<AuditEntry>
            size="small"
            rowKey={(row) => `${row.time}-${row.action}-${row.remoteIp || ''}`}
            dataSource={audit}
            pagination={{ pageSize: 12, showSizeChanger: true }}
            scroll={{ x: 760 }}
            columns={[
              { title: text.time, dataIndex: 'time', width: 190, render: (value: string) => new Date(value).toLocaleString() },
              { title: text.action, dataIndex: 'action' },
              { title: text.client, dataIndex: 'remoteIp', width: 150, render: (value?: string) => value || '—' },
              { title: text.result, dataIndex: 'success', width: 110, render: (value: boolean) => <Tag color={value ? 'success' : 'error'}>{value ? 'OK' : 'ERROR'}</Tag> },
              { title: ru ? 'Сообщение' : 'Message', dataIndex: 'message', ellipsis: true, render: (value?: string) => value || '—' },
            ]}
          />
        </Card>

        <Button type="primary" htmlType="submit" icon={<SaveOutlined />} loading={saving}>
          {text.save}
        </Button>
      </Space>
    </Form>
  );
}
