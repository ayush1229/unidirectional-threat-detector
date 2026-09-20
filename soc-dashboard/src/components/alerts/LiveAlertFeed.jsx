import { useMemo, useRef } from 'react';
import AlertRow from './AlertRow';
import EmptyState from '../common/EmptyState';
import { compareBySeverityThenTime } from '../../utils/severityUtils';
import { useAlertStore } from '../../store/alertStore';

const COLS = [
  'Severity', 'Threat Class', 'Confidence',
  'Source', 'Destination', 'Proto', 'Time', 'Flow ID', '',
];

export default function LiveAlertFeed({
  alerts,
  onSelect,
  sortBySeverity = false,
  title          = 'Live Alert Feed',
  maxHeight      = 'max-h-[440px]',
}) {
  const seenIds = useRef(new Set());

  const sorted = useMemo(() => {
    const list = [...alerts];
    if (sortBySeverity) {
      list.sort(compareBySeverityThenTime);
    } else {
      list.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }
    return list;
  }, [alerts, sortBySeverity]);

  const clearAlerts = useAlertStore((s) => s.clearAlerts);

  async function handleClear() {
    try {
      await fetch('/api/alerts', { method: 'DELETE' });
    } catch (_) {}
    clearAlerts();
  }

  return (
    <div id="live-feed" className="card flex flex-col overflow-hidden shadow-card">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-border/70 bg-surface-0/50 shrink-0">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-bold font-sans text-ink-primary tracking-tight">{title}</h3>
          <span className="rounded-full bg-forest-light border border-forest-border/40 px-2.5 py-0.5 mono text-2xs font-bold text-forest">
            {alerts.length}
          </span>
        </div>
        <div className="flex items-center gap-3">
          {sorted.length > 0 && (
            <button
              onClick={handleClear}
              className="text-2xs font-semibold text-ink-muted hover:text-red-600 hover:bg-red-50 transition-colors px-2.5 py-1 rounded-full bg-surface-2 border border-border"
              title="Clear all historical alerts"
            >
              Clear Feed
            </button>
          )}
          {sorted.length > 0 && (
            <div className="flex items-center gap-1.5 bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 rounded-full">
              <span className="h-2 w-2 rounded-full bg-mint animate-pulseDot shrink-0 shadow-2xs" />
              <span className="text-xs font-bold text-forest">Live</span>
            </div>
          )}
        </div>
      </div>

      {/* Body */}
      {sorted.length === 0
        ? <EmptyState title="No alerts to display" description="Adjust your filters or wait for new detections." />
        : (
          <div className={`overflow-auto ${maxHeight}`}>
            <table className="w-full border-collapse">
              <thead className="sticky top-0 z-10 bg-surface-2/90 backdrop-blur-sm">
                <tr>
                  {COLS.map((c, i) => (
                    <th
                      key={i}
                      className="px-4 py-3 text-left text-[11px] font-bold uppercase tracking-wider text-ink-secondary whitespace-nowrap border-b border-border"
                    >
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {sorted.map((alert) => {
                  const isNew = !seenIds.current.has(alert.flow_id);
                  seenIds.current.add(alert.flow_id);
                  return (
                    <AlertRow
                      key={alert.flow_id}
                      alert={alert}
                      onClick={onSelect}
                      isNew={isNew}
                    />
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
    </div>
  );
}
