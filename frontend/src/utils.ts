import { message } from 'antd';

export type Response<T> = { success: boolean; obj?: T; msg: string };
type RollbackEnvelope = { rollback?: { token?: string } };

let csrf = '';

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
): Promise<Response<T>> {
  const res = await fetch(path, {
    method: data === undefined ? 'GET' : 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  if (res.status === 401 && path !== '/api/login' && path !== '/api/session') {
    window.dispatchEvent(new Event('session-expired'));
  }
  const result: Response<T> = await res.json();
  if (!result.success && path !== '/api/session') {
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
  get: <T,>(path: string) => request<T>(path),
  post: async <T,>(
    path: string,
    data?: Record<string, unknown>,
    _options?: unknown,
  ): Promise<Response<T>> => {
    try {
      return await request<T>(path, data || {});
    } catch {
      void message.error('Не удалось связаться с сервером');
      return { success: false, msg: 'Network error' };
    }
  },
};
