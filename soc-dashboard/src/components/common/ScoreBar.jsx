/**
 * Refined horizontal score bar for model contributions in alert drill-down.
 */
export default function ScoreBar({ label, value, color = '#0B4F30' }) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return <div className="flex justify-between text-xs"><span>{label}</span><span className="text-ink-muted">Unavailable</span></div>;
  }
  const pct = Math.max(0, Math.min(1, value ?? 0)) * 100;
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-xs">
        <span className="font-semibold text-ink-secondary">{label}</span>
        <span className="mono text-ink-primary font-bold">{pct.toFixed(0)}%</span>
      </div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-surface-3 p-0.5 border border-border/50">
        <div
          className="h-full rounded-full transition-all duration-300 ease-out shadow-2xs"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}
