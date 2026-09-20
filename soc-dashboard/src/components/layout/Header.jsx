import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import ConnectionStatus from '../common/ConnectionStatus';
import PipelineStrip from './PipelineStrip';

const NAV = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/alerts', label: 'Alerts' },
];

export default function Header({ connectionStatus, latestAlert, sensorId, pipelineVersion }) {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <header className="sticky top-0 z-30 bg-surface-1/90 backdrop-blur-md border-b border-border/80 px-4 sm:px-6 py-3">
      <div className="flex items-center justify-between gap-4">

        {/* Logo & System Brand */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-forest text-white shadow-sm ring-2 ring-forest/20">
            <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="currentColor" fillOpacity="0.15" />
              <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <div>
            <div className="text-sm font-bold tracking-tight text-ink-primary leading-tight font-sans">SENTINEL-D</div>
            <div className="text-2xs font-medium text-ink-muted">SIH26145 · Passive Detector</div>
          </div>
        </div>

        {/* Navigation Tabs (Reference A active green pill style) */}
        <nav className="flex items-center gap-1.5 bg-surface-2 p-1 rounded-full border border-border/60">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              className={({ isActive }) =>
                `px-4 py-1.5 text-xs sm:text-sm rounded-full font-semibold transition-all duration-200 ${
                  isActive
                    ? 'bg-forest text-white shadow-sm'
                    : 'text-ink-secondary hover:text-forest hover:bg-forest-light/60'
                }`
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>

        {/* Pipeline strip */}
        <div className="hidden lg:flex flex-1 justify-center max-w-md">
          <PipelineStrip pulseKey={latestAlert?.flow_id} />
        </div>

        {/* Right cluster: Time, Connection & User Profile Pill (Reference B style) */}
        <div className="flex items-center gap-3 sm:gap-4 shrink-0">
          <div className="hidden sm:flex flex-col items-end gap-0.5">
            <span className="mono text-xs font-semibold text-ink-primary tabular-nums">
              {now.toLocaleTimeString(undefined, { hour12: false })}
            </span>
            <span className="text-2xs font-medium text-ink-muted">
              {now.toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' })}
            </span>
          </div>

          <div className="hidden sm:block h-5 w-px bg-border" />

          <ConnectionStatus status={connectionStatus} />

          {/* User Profile Pill Avatar (Ref B style) */}
          <div className="hidden xl:flex items-center gap-2.5 bg-surface-2 border border-border/80 rounded-full pl-2 pr-3 py-1">
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-forest text-white text-xs font-bold shadow-sm">
              SD
            </div>
            <div className="flex flex-col text-left">
              <span className="text-xs font-semibold text-ink-primary leading-tight">SOC Analyst</span>
              <span className="text-[10px] text-ink-muted leading-none">analyst@sentinel.io</span>
            </div>
          </div>
        </div>

      </div>
    </header>
  );
}
