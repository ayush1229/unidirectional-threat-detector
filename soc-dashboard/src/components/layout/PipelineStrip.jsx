import { useEffect, useState } from 'react';

const STAGES = ['AGENT 1', 'OBSERVATIONS', 'AGENT 2', 'DECISIONS', 'INCIDENTS'];

export default function PipelineStrip({ pulseKey }) {
  const [pulses, setPulses] = useState([]);

  useEffect(() => {
    if (pulseKey == null) return;
    const id = pulseKey;
    setPulses((p) => [...p, id]);
    const t = setTimeout(() => {
      setPulses((p) => p.filter((x) => x !== id));
    }, 2400);
    return () => clearTimeout(t);
  }, [pulseKey]);

  return (
    <div className="hidden items-center overflow-hidden lg:flex" aria-hidden="true">
      <div className="flex items-center gap-1.5 rounded-full border border-border bg-surface-2/80 px-3.5 py-1">
        {STAGES.map((stage, i) => (
          <div key={stage} className="flex items-center">
            <span className="mono text-[10px] font-bold tracking-wider text-ink-secondary">
              {stage}
            </span>
            {i < STAGES.length - 1 && (
              <div className="relative mx-2 h-px w-5 bg-border-strong">
                {pulses.map((p) => (
                  <span
                    key={`${p}-${i}`}
                    className="absolute left-0 top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full bg-mint shadow-sm animate-travel"
                  />
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
