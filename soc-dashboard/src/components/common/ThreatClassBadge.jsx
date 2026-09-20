import { threatClassShortLabel, threatClassColor } from '../../utils/threatUtils';

export default function ThreatClassBadge({ threatClass }) {
  const color = threatClassColor(threatClass);
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface-2 px-2.5 py-0.5 text-[11px] font-semibold text-ink-primary whitespace-nowrap shadow-2xs">
      <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: color }} />
      {threatClassShortLabel(threatClass)}
    </span>
  );
}
