export function describeAddress(address: string, family: string, ru = true) {
  const ipv6 = family === 'IPv6' || address.includes(':');
  const all = !address || address === '0.0.0.0' || address === '::';
  const local =
    address === '::1' ||
    address.startsWith('127.') ||
    address.startsWith('::ffff:127.');
  const label = all
    ? ru
      ? 'Все интерфейсы'
      : 'All interfaces'
    : local
      ? ru
        ? 'Только этот сервер'
        : 'This server only'
      : address;
  return {
    label,
    family: ipv6 ? 'IPv6' : 'IPv4',
    address: address || '0.0.0.0',
  };
}
export function socketEndpoint(address: string, port: number) {
  return `${address.includes(':') ? `[${address}]` : address}:${port}`;
}
