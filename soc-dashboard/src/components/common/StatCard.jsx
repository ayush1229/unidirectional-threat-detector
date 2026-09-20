export default function StatCard({ label, value, tone = 'default', sublabel }) {
  const toneClass = {
    default: 'text-ink-primary',
    critical: 'text-sev-critical',
    high: 'text-sev-high',
    medium: 'text-sev-medium',
    low: 'text-sev-low',
    signal: 'text-mint',
  }[tone];

  return (
    <div className="card flex flex-col justify-between p-4 shadow-card hover:border-forest-border/50 transition-all">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-ink-muted">{label}</span>
      <span className={`mt-1 font-mono text-2xl font-bold ${toneClass}`}>{value}</span>
      {sublabel && <span className="mt-0.5 text-[11px] font-medium text-ink-muted">{sublabel}</span>}
    </div>
  );
}
