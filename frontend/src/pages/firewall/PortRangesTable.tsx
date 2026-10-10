import { useMemo, useState } from 'react';
import { Collapse, Grid, Pagination, Table, Typography } from 'antd';
import {
  groupPortsByProcess,
  summarizePorts,
  type Port,
  type ProcessGroup,
} from './portGroups';
import { AddressLabel } from './PortLabels';

export default function PortRangesTable({
  ports,
  ru,
}: {
  ports: Port[];
  ru: boolean;
}) {
  const groups = useMemo(() => groupPortsByProcess(ports), [ports]);
  const screens = Grid.useBreakpoint();
  const [page, setPage] = useState(1);
  const visiblePage = Math.min(
    page,
    Math.max(1, Math.ceil(groups.length / 10)),
  );
  const summary = (group: ProcessGroup) => {
    const extent = summarizePorts(group.ports.map((port) => port.port));
    return (
      <div>
        <strong className="port-range">{extent.range}</strong>
        <div>
          <Typography.Text type="secondary">
            {ru ? 'Портов' : 'Ports'}: {extent.count} ·{' '}
            {[
              ...new Set(
                group.ports.map((port) => port.protocol.toUpperCase()),
              ),
            ].join(' / ')}
            {extent.sparse ? (ru ? ' · с пропусками' : ' · with gaps') : ''}
          </Typography.Text>
        </div>
      </div>
    );
  };
  const process = (group: ProcessGroup) => (
    <div>
      {[...new Set(group.processes.map((owner) => owner.name))].join(', ') ||
        '—'}
      <Typography.Text type="secondary">
        {' '}
        {group.processes.length <= 3
          ? ` · PID ${group.processes.map((owner) => owner.pid).join(', ')}`
          : ` · ${ru ? 'Процессов' : 'Processes'}: ${group.processes.length}`}
      </Typography.Text>
    </div>
  );
  const details = (group: ProcessGroup) => (
    <Table<Port>
      size="small"
      rowKey={(port) => `${port.family}-${port.protocol}-${port.socketId}`}
      dataSource={group.ports}
      pagination={{ pageSize: 10, hideOnSinglePage: true }}
      scroll={{ x: 650 }}
      columns={[
        {
          title: ru ? 'Порт' : 'Port',
          render: (_, port) => (
            <div>
              {port.port}/{port.protocol.toUpperCase()}
            </div>
          ),
          width: 110,
        },
        {
          title: ru ? 'Адрес' : 'Address',
          render: (_, port) => (
            <AddressLabel
              address={port.address}
              family={port.family}
              port={port.port}
              ru={ru}
            />
          ),
          width: 230,
        },
        {
          title: 'PID',
          render: (_, port) =>
            port.processes
              .map((owner) => `${owner.name} · ${owner.pid}`)
              .join(', '),
        },
      ]}
    />
  );
  if (!screens.md)
    return (
      <div>
        <Collapse
          items={groups
            .slice((visiblePage - 1) * 10, visiblePage * 10)
            .map((group) => ({
              key: group.id,
              label: (
                <div className="overview-range-label">
                  {process(group)}
                  {summary(group)}
                </div>
              ),
              children: details(group),
            }))}
        />
        <Pagination
          simple
          hideOnSinglePage
          pageSize={10}
          total={groups.length}
          current={visiblePage}
          onChange={setPage}
          style={{ marginTop: 12 }}
        />
      </div>
    );
  return (
    <Table<ProcessGroup>
      className="overview-ranges"
      size="small"
      rowKey="id"
      dataSource={groups}
      pagination={{ pageSize: 10, hideOnSinglePage: true }}
      scroll={{ x: 700 }}
      expandable={{ expandedRowRender: details }}
      columns={[
        {
          title: ru ? 'Диапазон портов' : 'Port range',
          render: (_, group) => summary(group),
          width: 220,
        },
        {
          title: ru ? 'Процесс' : 'Process',
          render: (_, group) => process(group),
        },
        {
          title: ru ? 'Адрес' : 'Address',
          width: 230,
          render: (_, group) =>
            [...new Set(group.ports.map((port) => port.address))].map(
              (address) => (
                <AddressLabel
                  key={address}
                  address={address}
                  family={address.includes(':') ? 'IPv6' : 'IPv4'}
                  ru={ru}
                />
              ),
            ),
        },
      ]}
    />
  );
}
