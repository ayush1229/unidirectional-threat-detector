import { useState } from 'react';
import { THREAT_CLASSES } from '../../types/alert';
import { threatClassShortLabel } from '../../utils/threatUtils';

const SEVERITY_OPTS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const TIME_OPTS = [
  { value: 'all', label: 'All time' },
  { value: '5m',  label: 'Last 5m'  },
  { value: '15m', label: 'Last 15m' },
  { value: '1h',  label: 'Last 1h'  },
  { value: '24h', label: 'Last 24h' },
];
const SEV_ACTIVE = {
  CRITICAL: 'border-sev-critical text-sev-critical bg-sev-criticalBg',
  HIGH:     'border-sev-high     text-sev-high     bg-sev-highBg',
  MEDIUM:   'border-sev-medium   text-sev-medium   bg-sev-mediumBg',
  LOW:      'border-sev-low      text-sev-low      bg-sev-lowBg',
};

export default function AlertFilters({
  filters, searchQuery,
  onSeverity, onThreat, onTimeRange, onSearch, onClear,
}) {
  const [threatOpen, setThreatOpen] = useState(false);
  const hasFilters =
    filters.severity !== 'ALL' ||
    filters.threatClass !== 'ALL' ||
    filters.timeRange !== 'all'  ||
    searchQuery;

  return (
    <div className="card p-4 sm:p-5 flex flex-col gap-3.5 shadow-card">

      {/* ── Search bar ─────────────────────────────────── */}
      <div className="relative">
        <svg
          className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-ink-muted"
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <circle cx="11" cy="11" r="8" /><path strokeLinecap="round" d="m21 21-4.35-4.35" />
        </svg>
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search by IP address, Flow ID, or threat class…"
          className="w-full rounded-full border border-border/80 bg-surface-2/70 py-2.5 pl-11 pr-10 text-xs sm:text-sm text-ink-primary font-medium placeholder:text-ink-muted outline-none focus:border-forest focus:bg-surface-1 focus:ring-2 focus:ring-forest-light transition-all shadow-2xs"
        />
        {searchQuery && (
          <button
            onClick={() => onSearch('')}
            className="absolute right-4 top-1/2 -translate-y-1/2 text-ink-muted hover:text-ink-primary"
          >
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>

      {/* ── Filter chips ───────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2 pt-0.5">

        {/* Severity */}
        {SEVERITY_OPTS.map((s) => {
          const isActive = filters.severity === s;
          const colorCls = isActive && s !== 'ALL' ? SEV_ACTIVE[s] : '';
          return (
            <button
              key={s}
              onClick={() => onSeverity(s)}
              className={`chip ${isActive ? (s === 'ALL' ? 'active' : colorCls) : ''}`}
            >
              {s === 'ALL' ? 'All Severity' : s[0] + s.slice(1).toLowerCase()}
            </button>
          );
        })}

        <div className="h-4 w-px bg-border mx-1 hidden sm:block" />

        {/* Time range */}
        {TIME_OPTS.map((t) => (
          <button
            key={t.value}
            onClick={() => onTimeRange(t.value)}
            className={`chip ${filters.timeRange === t.value ? 'active' : ''}`}
          >
            {t.label}
          </button>
        ))}

        <div className="h-4 w-px bg-border mx-1 hidden sm:block" />

        {/* Threat class dropdown */}
        <div className="relative">
          <button
            onClick={() => setThreatOpen((o) => !o)}
            className={`chip ${filters.threatClass !== 'ALL' ? 'active' : ''}`}
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 4h13M3 8h9m-9 4h6m4 0 4-4 4 4m-4-4v12" />
            </svg>
            {filters.threatClass === 'ALL' ? 'Threat class' : threatClassShortLabel(filters.threatClass)}
            <svg className={`h-3 w-3 transition-transform ${threatOpen ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="m19 9-7 7-7-7" />
            </svg>
          </button>

          {threatOpen && (
            <>
              {/* Backdrop */}
              <div className="fixed inset-0 z-10" onClick={() => setThreatOpen(false)} />
              <div className="absolute top-full left-0 z-20 mt-1.5 min-w-[210px] rounded-2xl border border-border bg-surface-1 shadow-elevated py-1.5 overflow-hidden">
                {[{ value: 'ALL', label: 'All classes' },
                  ...THREAT_CLASSES.map((c) => ({ value: c, label: threatClassShortLabel(c) }))
                ].map(({ value, label }) => (
                  <button
                    key={value}
                    onClick={() => { onThreat(value); setThreatOpen(false); }}
                    className={`w-full text-left px-4 py-2 text-xs font-medium transition-colors hover:bg-forest-light/60 hover:text-forest
                      ${filters.threatClass === value ? 'text-forest font-bold bg-forest-light' : 'text-ink-secondary'}`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Clear */}
        {hasFilters && (
          <button
            onClick={onClear}
            className="ml-auto text-xs font-semibold text-forest hover:underline underline-offset-4"
          >
            Clear filters
          </button>
        )}
      </div>
    </div>
  );
}
