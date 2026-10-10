import { Spin } from 'antd';

type Props = { label: string };

/** Consistent viewport-centered loading state for session checks and lazy pages. */
export default function FullScreenLoader({ label }: Props) {
  return (
    <div className="app-loading" role="status" aria-label={label} aria-live="polite">
      <Spin size="large" />
    </div>
  );
}
