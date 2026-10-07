import { message } from 'antd';
export type Response<T> = { success: boolean; obj?: T; msg: string };
let csrf = '';
export function setCSRF(value: string) { csrf = value; }
export async function request<T>(path: string, data?: Record<string, unknown>): Promise<Response<T>> {
  const res = await fetch(path, { method: data === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: data === undefined ? undefined : JSON.stringify(data) });
  if (res.status === 401 && path !== '/api/login' && path !== '/api/session') window.dispatchEvent(new Event('session-expired'));
  const result: Response<T> = await res.json();
  if (!result.success && path !== '/api/session') void message.error(result.msg || 'Ошибка запроса');
  return result;
}
export const HttpUtil = {
  get: <T,>(path: string) => request<T>(path),
  post: async <T,>(path: string, data?: Record<string, unknown>, _options?: unknown): Promise<Response<T>> => {
    try { return await request<T>(path, data || {}); }
    catch { void message.error('Не удалось связаться с сервером'); return { success: false, msg: 'Network error' }; }
  },
};
