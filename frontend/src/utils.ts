import { message } from 'antd';

export type Response<T> = { success: boolean; obj?: T; msg: string };
type RollbackEnvelope = { rollback?: { token?: string } };

let csrf = '';
let sessionRestarting = false;
let expirationPending = false;

export function setSessionRestarting(value: boolean) {
  sessionRestarting = value;
  if (!value && expirationPending) {
    expirationPending = false;
    window.dispatchEvent(new Event('session-expired'));
  }
}

export function setCSRF(value: string) {
  csrf = value;
}

function rollbackToken(value: unknown): string {
  if (!value || typeof value !== 'object') return '';
  const rollback = (value as RollbackEnvelope).rollback;
  return rollback?.token || '';
}

async function confirmRollback(token: string) {
  try {
    await fetch('/api/firewall/rollback/confirm', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ token }),
    });
  } catch {
    // Losing connectivity is exactly what the server-side rollback timer handles.
  }
}

export async function request<T>(
  path: string,
  data?: Record<string, unknown>,
  options: { silent?: boolean; signal?: AbortSignal; ignoreUnauthorized?: boolean } = {},
): Promise<Response<T>> {
  const res = await fetch(path, {
    signal: options.signal,
    method: data === undefined ? 'GET' : 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  if (!options.ignoreUnauthorized && res.status === 401 && path !== '/api/login' && path !== '/api/session') {
    if (sessionRestarting) expirationPending = true;
    else window.dispatchEvent(new Event('session-expired'));
  }
  const result: Response<T> = await res.json();
  if (!options.silent && !result.success && path === '/api/login') {
    void message.error(result.msg === 'invalid credentials'
      ? 'Неверный логин или пароль'
      : result.msg || 'Не удалось войти');
  }
  if (!options.silent && !result.success && path !== '/api/session' && path !== '/api/login' && res.status !== 401) {
    void message.error(result.msg || 'Ошибка запроса');
  }

  if (result.success && path !== '/api/firewall/rollback/confirm') {
    const token = rollbackToken(result.obj);
    if (token) {
      window.setTimeout(() => {
        void confirmRollback(token);
      }, 1200);
    }
  }
  return result;
}

export const HttpUtil = {
  get: async <T,>(path: string): Promise<Response<T>> => {
    try {
      return await request<T>(path);
    } catch {
      return { success: false, msg: 'Не удалось связаться с сервером' };
    }
  },
  post: async <T,>(
    path: string,
    data?: Record<string, unknown>,
  ): Promise<Response<T>> => {
    try {
      return await request<T>(path, data || {});
    } catch {
      void message.error('Не удалось связаться с сервером');
      return { success: false, msg: 'Network error' };
    }
  },
};
