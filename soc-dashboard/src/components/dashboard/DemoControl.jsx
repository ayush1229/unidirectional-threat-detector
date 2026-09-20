export default function DemoControl({ demo, onStart, onStop }) {
  return (
    <div className="card flex items-center justify-between gap-3 border-forest-border/40 bg-forest-light/60 px-5 py-3 rounded-2xl shadow-sm">
      <div className="flex items-center gap-3">
        <span className="h-2.5 w-2.5 rounded-full bg-mint animate-pulseDot shrink-0 shadow-sm" />
        <span className="text-xs font-bold text-forest tracking-wide font-sans">Demo Attack Simulator</span>
        {demo.active && (
          <>
            <span className="text-ink-muted">·</span>
            <span className="text-xs font-medium text-ink-secondary">{demo.stepLabel}</span>
          </>
        )}
      </div>

      {demo.active ? (
        <button
          onClick={onStop}
          className="rounded-full border border-red-200 bg-red-50 px-4 py-1.5 text-xs font-semibold text-red-600 hover:bg-red-100 transition-colors shadow-2xs"
        >
          Stop Simulation
        </button>
      ) : (
        <button
          onClick={onStart}
          className="rounded-full bg-forest px-4 py-1.5 text-xs font-semibold text-white hover:bg-forest-hover transition-all duration-200 shadow-sm"
        >
          Run Attack Simulation
        </button>
      )}
    </div>
  );
}
