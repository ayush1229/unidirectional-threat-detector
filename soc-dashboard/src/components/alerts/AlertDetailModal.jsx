import { useEffect, useRef } from 'react';
import SeverityBadge from '../common/SeverityBadge';
import ThreatClassBadge from '../common/ThreatClassBadge';
import ModelContribution from './ModelContribution';
import EvidencePanel from './EvidencePanel';
import DecisionDetails from './DecisionDetails';
import { formatTimestamp, formatConfidence } from '../../utils/alertFormatters';

function DataItem({ label, value, mono = true }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-[10px] font-bold uppercase tracking-wider text-ink-muted">{label}</dt>
      <dd className={`text-xs text-ink-primary font-semibold ${mono ? 'mono' : ''}`}>{value ?? '—'}</dd>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <section className="space-y-2.5">
      <div className="flex items-center gap-2">
        <h4 className="text-2xs font-bold uppercase tracking-wider text-forest font-sans">{title}</h4>
        <div className="h-px flex-1 bg-border/80" />
      </div>
      {children}
    </section>
  );
}

export default function AlertDetailModal({ alert, onClose }) {
  const closeBtnRef = useRef(null);

  useEffect(() => {
    closeBtnRef.current?.focus();
    function onKeyDown(e) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onClose]);

  if (!alert) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-forest-dark/40 p-4 pt-10 backdrop-blur-md sm:pt-14 animate-fadeUp"
      role="dialog"
      aria-modal="true"
      aria-label="Alert details"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="card w-full max-w-2xl overflow-hidden shadow-modal border-forest-border/40 rounded-3xl bg-surface-1">
        {/* Header */}
        <div className="flex items-start justify-between gap-4 border-b border-border/80 bg-forest-light/50 px-6 py-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={alert.severity} />
              <ThreatClassBadge threatClass={alert.threat_class} />
            </div>
            <p className="mono text-xs font-medium text-ink-muted">
              Flow ID: <span className="text-forest font-bold">{alert.flow_id}</span>
            </p>
          </div>
          <button
            ref={closeBtnRef}
            onClick={onClose}
            aria-label="Close alert details"
            className="rounded-full border border-border bg-white p-1.5 text-ink-muted transition-all hover:bg-forest hover:text-white hover:border-forest shadow-2xs"
          >
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="max-h-[70vh] space-y-6 overflow-y-auto px-6 py-5">
          <DecisionDetails alert={alert} />
          <Section title="General Information">
            <dl className="grid grid-cols-2 gap-3.5 sm:grid-cols-3 rounded-2xl border border-border/70 bg-surface-2/60 p-4 shadow-2xs">
              <DataItem label="Confidence" value={formatConfidence(alert.confidence_score)} />
              <DataItem label="Timestamp" value={formatTimestamp(alert.timestamp)} />
              <DataItem label="Protocol" value={alert.five_tuple.protocol} />
              <DataItem label="Sensor ID" value={alert.ingestion_meta?.sensor_id} />
              <DataItem label="Capture Interface" value={alert.ingestion_meta?.capture_interface} />
              <DataItem label="Pipeline Version" value={alert.ingestion_meta?.pipeline_version} />
            </dl>
          </Section>

          <Section title="Network 5-Tuple">
            <dl className="grid grid-cols-2 gap-3.5 sm:grid-cols-4 rounded-2xl border border-border/70 bg-surface-2/60 p-4 shadow-2xs">
              <DataItem label="Source IP" value={alert.five_tuple.src_ip} />
              <DataItem label="Source Port" value={alert.five_tuple.src_port} />
              <DataItem label="Destination IP" value={alert.five_tuple.dst_ip} />
              <DataItem label="Dest Port" value={alert.five_tuple.dst_port} />
            </dl>
          </Section>

          <Section title="Model Ensemble Contribution">
            <ModelContribution modelSource={alert.model_source} />
          </Section>

          <Section title="Extracted Forensic Evidence">
            <EvidencePanel evidence={alert.evidence} />
          </Section>
        </div>

        {/* Footer */}
        <div className="border-t border-border/80 bg-surface-2/40 px-6 py-3.5 text-center sm:text-left">
          <p className="text-2xs font-medium text-ink-muted">
            Unidirectional passive detection record. This alert is advisory for SOC analyst review.
          </p>
        </div>
      </div>
    </div>
  );
}
