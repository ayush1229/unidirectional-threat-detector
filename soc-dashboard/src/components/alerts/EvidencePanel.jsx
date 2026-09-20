import { formatEvidenceKey } from '../../utils/threatUtils';
import { formatEvidenceValue as fmtVal } from '../../utils/alertFormatters';

export default function EvidencePanel({ evidence }) {
  const entries = Object.entries(evidence ?? {});

  if (entries.length === 0) {
    return <p className="text-xs font-medium text-ink-muted">No supporting evidence attached to this alert.</p>;
  }

  return (
    <dl className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
      {entries.map(([key, value]) => (
        <div key={key} className="rounded-xl border border-border/70 bg-surface-2/60 p-3 shadow-2xs">
          <dt className="text-[10px] font-bold uppercase tracking-wider text-ink-muted">
            {formatEvidenceKey(key)}
          </dt>
          <dd className="mt-1 truncate mono text-xs text-ink-primary font-bold" title={fmtVal(value)}>
            {fmtVal(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}
