import type { PageKey } from '@/layouts/AppSidebar';

const pages: readonly PageKey[] = ['firewall', 'overview', 'ports', 'settings'];

export function getPageFromHash(hash: string): PageKey {
  const key = hash.replace(/^#\/?/, '').toLowerCase();
  return pages.find((page) => page === key) ?? 'firewall';
}
