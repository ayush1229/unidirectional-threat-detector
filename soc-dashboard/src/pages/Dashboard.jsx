import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAlertStore, selectStats } from '../store/alertStore';
import SummaryStats from '../components/dashboard/SummaryStats';
import ThreatActivityChart from '../components/dashboard/ThreatActivityChart';
import ThreatDistributionChart from '../components/dashboard/ThreatDistributionChart';
import ThroughputChart from '../components/dashboard/ThroughputChart';
import EntropyChart from '../components/dashboard/EntropyChart';
import DemoControl from '../components/dashboard/DemoControl';
import LiveAlertFeed from '../components/alerts/LiveAlertFeed';
import IncidentFeed from '../components/dashboard/IncidentFeed';
import PipelineControl from '../components/dashboard/PipelineControl';
import { useLiveDemo } from '../hooks/useLiveDemo';
import { exportAlertsToJson } from '../utils/exportUtils';

const USE_MOCK = String(import.meta.env.VITE_USE_MOCK_DATA).toLowerCase() === 'true';

export default function Dashboard() {
  const alerts = useAlertStore((s) => s.alerts);
  const stats = useAlertStore(selectStats);
  const demo = useAlertStore((s) => s.demo);
  const selectAlert = useAlertStore((s) => s.selectAlert);
  const { start, stop } = useLiveDemo();
  const navigate = useNavigate();
  const [exported, setExported] = useState(false);

  const recentAlerts = useMemo(() => alerts.slice(0, 25), [alerts]);

  function openAlert(alert) {
    selectAlert(alert);
    navigate(`/alerts/${alert.flow_id}`);
  }

  function handleExportLogs() {
    exportAlertsToJson(alerts);
    setExported(true);
    setTimeout(() => setExported(false), 2500);
  }

  function handleLiveMonitor() {
    navigate('/alerts');
  }

  return (
    <div className="mx-auto flex max-w-[1600px] flex-col gap-6 px-4 sm:px-6 py-6 animate-fadeUp">
      {/* Page Title Header (Reference A style) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-ink-primary font-sans tracking-tight">Dashboard</h1>
          <p className="text-xs sm:text-sm font-medium text-ink-muted mt-1">
            Plan, prioritize, and monitor passive threat detections with ease.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={handleExportLogs}
            className="px-4 py-2 text-xs font-bold text-forest bg-forest-light hover:bg-forest/15 rounded-full border border-forest-border/50 transition-all duration-200 shadow-2xs flex items-center gap-1.5"
            title="Download complete forensic threat telemetry as JSON"
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            {exported ? 'Logs Downloaded ✓' : 'Export Logs'}
          </button>
          <button
            onClick={handleLiveMonitor}
            className="px-4 py-2 text-xs font-bold text-white bg-forest hover:bg-forest-hover rounded-full transition-all duration-200 shadow-sm flex items-center gap-2 group"
            title="Open Live Threat Registry & Monitoring Stream"
          >
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-300"></span>
            </span>
            Live Monitor
            <svg className="h-3.5 w-3.5 text-white/80 transition-transform duration-200 group-hover:translate-x-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
          </button>
        </div>
      </div>

      {USE_MOCK && <DemoControl demo={demo} onStart={start} onStop={stop} />}
      {!USE_MOCK && <PipelineControl />}

      {/* Summary Stats Row */}
      <SummaryStats stats={stats} />
      <IncidentFeed />

      {/* Analytics Charts Grid */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
        <ThreatActivityChart alerts={alerts} />
        <ThreatDistributionChart alerts={alerts} />
        <ThroughputChart alerts={alerts} />
        <EntropyChart alerts={alerts} />
      </div>

      {/* Live Feed */}
      <LiveAlertFeed alerts={recentAlerts} onSelect={openAlert} title="Recent Ingested Alerts" />
    </div>
  );
}
