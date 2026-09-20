const CONFIG = {
  CONNECTED:    { label: 'Live Stream',   dot: 'bg-mint animate-pulseDot', text: 'text-forest font-bold' },
  CONNECTING:   { label: 'Connecting',   dot: 'bg-ink-muted animate-pulseDot', text: 'text-ink-secondary font-semibold' },
  RECONNECTING: { label: 'Reconnecting', dot: 'bg-amber-500 animate-pulseDot', text: 'text-amber-700 font-semibold' },
  DISCONNECTED: { label: 'Offline',      dot: 'bg-red-500', text: 'text-red-600 font-semibold' },
};

export default function ConnectionStatus({ status }) {
  const cfg = CONFIG[status] ?? CONFIG.DISCONNECTED;
  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-border/80 bg-surface-2 px-3 py-1 text-xs shadow-2xs" role="status" aria-live="polite">
      <span className={`h-2 w-2 rounded-full shrink-0 ${cfg.dot}`} />
      <span className={`text-xs ${cfg.text}`}>{cfg.label}</span>
    </div>
  );
}
