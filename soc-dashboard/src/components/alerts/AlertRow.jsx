import SeverityBadge from '../common/SeverityBadge';
import ThreatClassBadge from '../common/ThreatClassBadge';
import { formatClock, formatConfidence, formatFlowId } from '../../utils/alertFormatters';

// Thin left-border accent for critical rows
const criticalClass = 'border-l-4 border-l-red-500 bg-red-50/30 font-semibold';

export default function AlertRow({ alert, onClick, isNew }) {
  const isCritical = alert.severity === 'CRITICAL';
  const conf = typeof alert.confidence_score === 'number' ? Math.round(alert.confidence_score * 100) : null;

  return (
    <tr
      onClick={() => onClick(alert)}
      className={`trow ${isCritical ? criticalClass : ''} ${isNew ? 'animate-slideIn' : ''}`}
    >
      {/* Severity */}
      <td className="px-4 py-3.5 whitespace-nowrap">
        <SeverityBadge severity={alert.severity} size="sm" />
      </td>

      {/* Threat class */}
      <td className="px-4 py-3.5 whitespace-nowrap">
        <ThreatClassBadge threatClass={alert.threat_class} />
        {alert.decision_state && <div className="text-[10px] text-ink-muted mt-1">{alert.decision_state} {Object.keys(alert.labels || {}).length > 1 ? `+${Object.keys(alert.labels).length - 1} labels` : ''}</div>}
      </td>

      {/* Confidence — mini bar + number */}
      <td className="px-4 py-3.5 whitespace-nowrap">
        <div className="flex items-center gap-2.5">
          <div className="w-16 h-1.5 rounded-full bg-surface-3 overflow-hidden shrink-0 border border-border/40">
            <div
              className="h-full rounded-full bg-forest"
              style={{ width: `${conf ?? 0}%` }}
            />
          </div>
          <span className="mono text-[11px] font-bold text-ink-primary">{formatConfidence(alert.confidence_score)}</span>
        </div>
      </td>

      {/* Source IP */}
      <td className="px-4 py-3.5 whitespace-nowrap mono text-[11px] font-medium text-ink-primary">
        {alert.five_tuple.src_ip}
        <span className="text-ink-muted">:{alert.five_tuple.src_port}</span>
      </td>

      {/* Dest IP */}
      <td className="px-4 py-3.5 whitespace-nowrap mono text-[11px] font-medium text-ink-primary">
        {alert.five_tuple.dst_ip}
        <span className="text-ink-muted">:{alert.five_tuple.dst_port}</span>
      </td>

      {/* Protocol */}
      <td className="px-4 py-3.5 whitespace-nowrap">
        <span className="inline-block rounded-full bg-forest-light px-2 py-0.5 mono text-[10px] font-bold text-forest border border-forest-border/40">
          {alert.five_tuple.protocol}
        </span>
      </td>

      {/* Time */}
      <td className="px-4 py-3.5 whitespace-nowrap mono text-[11px] text-ink-muted">
        {formatClock(alert.timestamp)}
      </td>

      {/* Flow ID */}
      <td className="px-4 py-3.5 whitespace-nowrap mono text-[11px] text-ink-muted">
        {formatFlowId(alert.flow_id)}
      </td>

      {/* Arrow */}
      <td className="px-3 py-3.5 text-ink-muted group-hover:text-forest">
        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
      </td>
    </tr>
  );
}
