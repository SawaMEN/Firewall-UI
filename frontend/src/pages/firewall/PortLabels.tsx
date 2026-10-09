import { Tag, Typography } from 'antd';
import { describeAddress, socketEndpoint } from './address';
import type { Port, PortService } from './portGroups';

export function AddressLabel({
  address,
  family,
  port,
  ru,
}: {
  address: string;
  family: string;
  port?: number;
  ru: boolean;
}) {
  const description = describeAddress(address, family, ru);
  return (
    <div className="bind-address">
      <span>
        {description.label}{' '}
        <Typography.Text type="secondary">
          · {description.family}
        </Typography.Text>
      </span>
      <Typography.Text
        type="secondary"
        copyable={{
          text: port
            ? socketEndpoint(description.address, port)
            : description.address,
        }}
      >
        {port ? socketEndpoint(description.address, port) : description.address}
      </Typography.Text>
    </div>
  );
}

export function PurposeLabels({ ports, ru }: { ports: Port[]; ru: boolean }) {
  const services = [
    ...new Map(
      ports
        .flatMap((port) => port.services || [])
        .map((service) => [service.id, service]),
    ).values(),
  ];
  if (!services.length) return null;
  return (
    <div className="port-purpose">
      {services.slice(0, 3).map((service) => (
        <div key={service.id}>
          <Tag color="cyan">3X-UI</Tag>
          <strong>
            {service.name || `${ru ? 'Инбаунд' : 'Inbound'} #${service.id}`}
          </strong>
          <Typography.Text type="secondary">
            {[
              service.protocol.toUpperCase(),
              service.transport,
              service.security,
            ]
              .filter(Boolean)
              .join(' · ')}
          </Typography.Text>
        </div>
      ))}
      {services.length > 3 ? (
        <Typography.Text type="secondary">
          {ru ? 'Инбаундов' : 'Inbounds'}: {services.length} ·{' '}
          {ru ? 'точные назначения внутри' : 'expand for details'}
        </Typography.Text>
      ) : null}
    </div>
  );
}

export function InboundProtocolTags({
  services = [],
}: {
  services?: PortService[];
}) {
  const protocols = [
    ...new Set(
      services.map((service) => service.protocol.toUpperCase()).filter(Boolean),
    ),
  ];
  return protocols.length ? (
    <span className="inbound-protocol-tags">
      {protocols.map((protocol) => (
        <Tag key={protocol} color="cyan" title="Протокол инбаунда 3X-UI">
          {protocol}
        </Tag>
      ))}
    </span>
  ) : null;
}
