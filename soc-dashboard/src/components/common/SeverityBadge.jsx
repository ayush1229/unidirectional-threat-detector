import { SEVERITY_META } from '../../utils/severityUtils';

export default function SeverityBadge({ severity, size = 'md' }) {
  const meta       = SEVERITY_META[severity] ?? SEVERITY_META.LOW;
  const isSmall    = size === 'sm';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-bold uppercase tracking-wider mono border border-current/10
        ${isSmall ? 'text-[10px] px-2 py-0.5' : 'text-[11px] px-2.5 py-1'}
        ${meta.bg} ${meta.text}`}
      style={{ letterSpacing: '0.05em' }}
    >
      <span className={`rounded-full shrink-0 ${isSmall ? 'h-1.5 w-1.5' : 'h-2 w-2'} ${meta.dot}`} />
      {meta.label}
    </span>
  );
}
