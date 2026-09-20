/**
 * Hybrid Stat Cards Row:
 * - Card 1: Deep forest green hero card for Total Alerts (Reference A style)
 * - Cards 2-6: Floating white cards with circular accent icon badges (Teal, Orange, Purple, Blue) (Reference B style)
 */
import { usePipelineStats } from '../../hooks/usePipelineStats';

function StatCardItem({ label, value, isHero = false, badgeColor, icon, trendLabel }) {
  if (isHero) {
    return (
      <div className="flex-1 min-w-[200px] rounded-2xl bg-forest p-5 text-white shadow-card relative overflow-hidden flex flex-col justify-between">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-white/80 tracking-wide">{label}</span>
          <div className="flex h-7 w-7 items-center justify-center rounded-full bg-white/20 text-white backdrop-blur-sm">
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M7 17L17 7M17 7H7M17 7V17" />
            </svg>
          </div>
        </div>

        <div className="mt-3">
          <span className="mono text-3xl font-extrabold tracking-tight text-white leading-none">{value}</span>
        </div>

        <div className="mt-3 flex items-center gap-1.5">
          <span className="inline-flex items-center gap-1 rounded-full bg-white/15 px-2 py-0.5 text-2xs font-semibold text-emerald-200">
            <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 10l7-7 7 7M12 3v18" />
            </svg>
            Active Stream
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="card flex-1 min-w-[170px] p-5 flex flex-col justify-between hover:border-forest-border/60 transition-all duration-200">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-ink-muted">{label}</span>
        <div className={`flex h-8 w-8 items-center justify-center rounded-full ${badgeColor.bg} ${badgeColor.text} shadow-2xs`}>
          {icon}
        </div>
      </div>

      <div className="mt-3 flex items-baseline justify-between">
        <span className={`mono text-2xl font-bold tracking-tight leading-none ${badgeColor.valueText || 'text-ink-primary'}`}>
          {value}
        </span>
      </div>

      {trendLabel && (
        <span className="mt-2 text-[10px] font-medium text-ink-muted">
          {trendLabel}
        </span>
      )}
    </div>
  );
}

export default function SummaryStats({ stats }) {
  const { flowsPerSec } = usePipelineStats();

  const flowsDisplay = flowsPerSec !== null
    ? flowsPerSec.toFixed(1)
    : '—';

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-4">
      <StatCardItem
        label="Total Alerts"
        value={stats.total}
        isHero={true}
      />
      <StatCardItem
        label="Critical Severity"
        value={stats.critical}
        badgeColor={{ bg: 'bg-red-100', text: 'text-red-600', valueText: 'text-red-600' }}
        icon={
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        }
        trendLabel="High Urgency"
      />
      <StatCardItem
        label="High Severity"
        value={stats.high}
        badgeColor={{ bg: 'bg-orange-100', text: 'text-orange-600', valueText: 'text-orange-600' }}
        icon={
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        }
        trendLabel="Requires Analyst Review"
      />
      <StatCardItem
        label="Medium Severity"
        value={stats.medium}
        badgeColor={{ bg: 'bg-amber-100', text: 'text-amber-600', valueText: 'text-amber-600' }}
        icon={
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        }
        trendLabel="Moderate Priority"
      />
      <StatCardItem
        label="Low Severity"
        value={stats.low}
        badgeColor={{ bg: 'bg-blue-100', text: 'text-blue-600', valueText: 'text-blue-600' }}
        icon={
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        }
        trendLabel="Informational Detections"
      />
      <StatCardItem
        label="Active Flows"
        value={stats.activeFlows}
        badgeColor={{ bg: 'bg-teal-100', text: 'text-teal-700', valueText: 'text-teal-700' }}
        icon={
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
          </svg>
        }
        trendLabel="Tracked Network Sessions"
      />
      <StatCardItem
        label="Flows / sec"
        value={flowsDisplay}
        badgeColor={{ bg: 'bg-emerald-100', text: 'text-emerald-700', valueText: 'text-emerald-700' }}
        icon={
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        }
        trendLabel="Real-time Throughput"
      />
    </div>
  );
}
