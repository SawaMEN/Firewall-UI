import { useMemo } from 'react';
import { Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { formatProtocols, pairProtocolRules } from './portGroups';

type Row<T> = T & { members?: T[]; groupId?: string };

type Props<T> = {
  rules: T[];
  identity: (rule: T) => string;
  rowKey: (rule: T) => string;
  columns: ColumnsType<Row<T>>;
  ru: boolean;
  scroll?: { x: number };
};
export function ProtocolRulesTable<T extends { protocol: string }>({
  rules, identity, rowKey, columns, ru, scroll,
}: Props<T>) {
  const rows = useMemo(() => pairProtocolRules(rules, identity).map((group) => ({
    ...group.rules[0], groupId: group.id, members: group.rules,
  })), [rules, identity]);
  const groupedColumns: ColumnsType<Row<T>> = columns.map((column) => {
    if ('dataIndex' in column && column.dataIndex === 'protocol') return {
      ...column, render: (_, rule) => <Tag>{formatProtocols(
        (rule.members || [rule]).map((member) => member.protocol), ' / ',
      )}</Tag>,
    };
    if (column.title === '') return {
      ...column, render: (value, rule, index) => rule.members && rule.members.length > 1
        ? <Typography.Text type="secondary">{ru ? 'Раскройте список' : 'Expand rules'}</Typography.Text>
        : column.render?.(value, rule, index),
    };
    return column;
  });
  return <Table<Row<T>>
    size="small" pagination={false} scroll={scroll}
    rowKey={(rule) => rule.groupId || rowKey(rule)} dataSource={rows}
    columns={groupedColumns}
    expandable={{
      rowExpandable: (rule) => !!rule.members && rule.members.length > 1,
      expandedRowRender: (rule) => <Table<Row<T>> size="small" pagination={false}
        scroll={scroll} rowKey={rowKey} dataSource={rule.members} columns={columns} />,
    }}
  />;
}
