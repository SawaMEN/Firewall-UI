import { Typography } from 'antd';
import { describeAddress, socketEndpoint } from './address';

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
