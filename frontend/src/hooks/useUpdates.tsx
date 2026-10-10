import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { Alert, App, Button, Modal, Space, Spin, Typography } from 'antd';
import { CloudDownloadOutlined } from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { request, setSessionRestarting } from '@/utils';
import { usePageVisibility } from './usePageVisibility';

export type UpdateStatus = {
  currentVersion: string;
  currentChannel: string;
  latestVersion: string;
  latestCommit: string;
  selectedChannel: string;
  available: boolean;
  restarting?: boolean;
  applying?: boolean;
  phase?: string;
  manualInstall?: boolean;
};

type Updates = {
  status: UpdateStatus | null;
  checking: boolean;
  busy: boolean;
  error: string;
  check: () => Promise<void>;
  confirm: () => void;
};
const Context = createContext<Updates | null>(null);
const installer = 'curl -fsSL https://raw.githubusercontent.com/SawaMEN/Firewall-UI/main/install.sh | sudo bash';

export function UpdateProvider({ children }: { children: ReactNode }) {
  const { i18n } = useTranslation();
  const ru = i18n.language.startsWith('ru');
  const { modal } = App.useApp();
  const visible = usePageVisibility();
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [checking, setChecking] = useState(false);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState('checking');
  const [error, setError] = useState('');
  const [failure, setFailure] = useState('');
  const running = useRef(false);
  const lifetime = useRef(new AbortController());
  const failed = ru ? 'Не удалось проверить обновление' : 'Update check failed';

  useEffect(() => {
    lifetime.current = new AbortController();
    const controller = lifetime.current;
    return () => { controller.abort(); setSessionRestarting(false); };
  }, []);

  const check = useCallback(async () => {
    if (running.current) return;
    const signal = lifetime.current.signal;
    setChecking(true);
    try {
      const result = await request<UpdateStatus>('/api/update/status', undefined, {
        silent: true, signal: AbortSignal.any([signal, AbortSignal.timeout(22000)]),
      });
      if (signal.aborted) return;
      if (result.success && result.obj) { setStatus(result.obj); setError(''); }
      else setError(result.msg || failed);
    } catch {
      if (!signal.aborted) setError(failed);
    } finally {
      if (!signal.aborted) setChecking(false);
    }
  }, [failed]);

  useEffect(() => {
    if (!visible) return;
    void check();
    const timer = window.setInterval(() => void check(), 5 * 60 * 1000);
    return () => window.clearInterval(timer);
  }, [visible, check]);

  // The status endpoint returns local progress while an update is running.
  useEffect(() => {
    if (!busy) return;
    const controller = new AbortController();
    let pending = false;
    const timer = window.setInterval(async () => {
      if (pending) return;
      pending = true;
      try {
        const result = await request<UpdateStatus>('/api/update/status', undefined, {
          silent: true, ignoreUnauthorized: true,
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(2500)]),
        });
        if (!controller.signal.aborted && result.obj?.phase) setPhase(result.obj.phase);
      } catch { /* The service can be unreachable during restart. */ }
      finally { pending = false; }
    }, 2000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [busy]);

  async function apply() {
    if (running.current || !status || status.manualInstall) return;
    running.current = true;
    setSessionRestarting(true);
    const signal = lifetime.current.signal;
    const target = { version: status.latestVersion, commit: status.latestCommit };
    setBusy(true);
    setFailure('');
    setPhase('checking');
    try {
      try {
        const result = await request<UpdateStatus>('/api/update/apply', {}, {
          silent: true, ignoreUnauthorized: true,
          signal: AbortSignal.any([signal, AbortSignal.timeout(130000)]),
        });
        if (signal.aborted) return;
        if (!result.success || !result.obj) throw new Error(result.msg || (ru ? 'Обновление не выполнено' : 'Update failed'));
        setStatus(result.obj);
        if (!result.obj.restarting) { setBusy(false); setSessionRestarting(false); return; }
        target.version = result.obj.latestVersion;
        target.commit = result.obj.latestCommit;
      } catch (err) {
        if (signal.aborted) return;
        // A lost HTTP response does not prove that installation failed.
        if (err instanceof Error && err.name !== 'TypeError' && err.name !== 'TimeoutError' && err.name !== 'AbortError') throw err;
      }
      setPhase('restarting');
      const deadline = Date.now() + 90000;
      while (!signal.aborted && Date.now() < deadline) {
        try {
          const result = await request<{ version: string; commit: string }>('/api/health', undefined, {
            silent: true, signal: AbortSignal.any([signal, AbortSignal.timeout(2000)]),
          });
          if (!signal.aborted && result.success && result.obj?.version === target.version && result.obj.commit === target.commit) {
            window.location.reload();
            return;
          }
        } catch { /* Wait until the new process answers. */ }
        await new Promise(resolve => window.setTimeout(resolve, 1200));
      }
      if (!signal.aborted) throw new Error(ru
        ? 'Не удалось подтвердить запуск новой версии. Проверьте журнал службы и обновите страницу.'
        : 'Could not confirm the new version has started. Check the service log and refresh the page.');
    } catch (err) {
      if (!signal.aborted) {
        const detail = err instanceof Error ? err.message : String(err);
        setError(detail);
        setFailure(detail);
      }
    } finally {
      if (!signal.aborted) { running.current = false; setBusy(false); }
    }
  }

  function confirm() {
    if (!status || running.current) return;
    if (status.manualInstall) {
      modal.info({
        title: ru ? 'Обновление Docker' : 'Docker update',
        content: <Space orientation="vertical" style={{ width: '100%' }}>
          <Typography.Paragraph>{ru ? 'Выполните на сервере команду, выберите «1 — Установить / обновить», затем «2 — Docker Compose».' : 'Run this command on the server, select “1 — Install / update”, then “2 — Docker Compose”.'}</Typography.Paragraph>
          <Typography.Paragraph copyable style={{ overflowWrap: 'anywhere' }}><code>{installer}</code></Typography.Paragraph>
        </Space>,
      });
      return;
    }
    modal.confirm({
      title: ru ? `Установить Firewall-UI ${status.latestVersion}?` : `Install Firewall-UI ${status.latestVersion}?`,
      content: ru ? 'Панель перезапустится. Дождитесь завершения обновления.' : 'The panel will restart. Wait for the update to finish.',
      okText: ru ? 'Установить' : 'Install', cancelText: ru ? 'Отмена' : 'Cancel',
      onOk: () => { void apply(); },
    });
  }

  const phases: Record<string, string> = ru ? {
    checking: 'Проверка обновления…', downloading: 'Загрузка и проверка SHA-256…',
    installing: 'Установка новой версии…', restarting: 'Перезапуск и проверка новой версии…',
  } : {
    checking: 'Checking update…', downloading: 'Downloading and verifying SHA-256…',
    installing: 'Installing new version…', restarting: 'Restarting and checking new version…',
  };
  return <Context.Provider value={{ status, checking, busy, error, check, confirm }}>
    {children}
    <Modal open={busy || Boolean(failure)} title={ru ? 'Обновление Firewall-UI' : 'Updating Firewall-UI'}
      closable={!busy} maskClosable={!busy} keyboard={!busy} onCancel={() => { setFailure(''); setSessionRestarting(false); }}
      footer={busy ? null : <Button onClick={() => window.location.reload()}>{ru ? 'Обновить страницу' : 'Refresh page'}</Button>}>
      {busy ? <Space orientation="vertical" align="center" style={{ display: 'flex', padding: '24px 0', textAlign: 'center' }}>
        <Spin size="large" /><Typography.Text strong>{phases[phase] || phases.checking}</Typography.Text>
        <Typography.Text type="secondary">{ru ? 'Не закрывайте и не обновляйте страницу.' : 'Keep this page open until the update finishes.'}</Typography.Text>
      </Space> : <Alert type="error" showIcon title={ru ? 'Обновление не подтверждено' : 'Update not confirmed'} description={failure} />}
    </Modal>
  </Context.Provider>;
}

export function useUpdates() {
  const value = useContext(Context);
  if (!value) throw new Error('UpdateProvider is required');
  return value;
}

export function UpdateNotice() {
  const { status, busy, confirm } = useUpdates();
  const { i18n } = useTranslation();
  const ru = i18n.language.startsWith('ru');
  if (!status?.available) return null;
  return <Alert className="update-banner" type="info" showIcon icon={<CloudDownloadOutlined />}
    title={ru ? `Доступно обновление Firewall-UI ${status.latestVersion}` : `Firewall-UI ${status.latestVersion} is available`}
    action={<Button type="primary" size="small" loading={busy} onClick={confirm} disabled={status.selectedChannel === 'dev' && !status.manualInstall}>
      {status.manualInstall ? (ru ? 'Как обновить' : 'How to update') : status.selectedChannel === 'dev' ? (ru ? 'Автообновление' : 'Automatic update') : (ru ? 'Обновить' : 'Update')}
    </Button>} />;
}
