import { useState } from 'react';
import { useNavigate, Outlet } from 'react-router-dom';
import { useAlertStore, selectFilteredAlerts } from '../store/alertStore';
import AlertFilters from '../components/alerts/AlertFilters';
import LiveAlertFeed from '../components/alerts/LiveAlertFeed';
import { exportAlertsToJson } from '../utils/exportUtils';

export default function Alerts() {
  const filters = useAlertStore((s) => s.filters);
  const searchQuery = useAlertStore((s) => s.searchQuery);
  const setSeverityFilter = useAlertStore((s) => s.setSeverityFilter);
  const setThreatFilter = useAlertStore((s) => s.setThreatFilter);
  const setTimeRangeFilter = useAlertStore((s) => s.setTimeRangeFilter);
  const setSearchQuery = useAlertStore((s) => s.setSearchQuery);
  const clearFilters = useAlertStore((s) => s.clearFilters);
  const selectAlert = useAlertStore((s) => s.selectAlert);
  const filtered = useAlertStore(selectFilteredAlerts);
  const navigate = useNavigate();
  const [exported, setExported] = useState(false);

  function openAlert(alert) {
    selectAlert(alert);
    navigate(`/alerts/${alert.flow_id}`);
  }

  function handleExport() {
    exportAlertsToJson(filtered, 'sentinel-filtered-threat-alerts');
    setExported(true);
    setTimeout(() => setExported(false), 2500);
  }

  return (
    <div className="mx-auto flex max-w-[1600px] flex-col gap-5 px-4 sm:px-6 py-6 animate-fadeUp">
      {/* Page Title Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-ink-primary font-sans tracking-tight">Threat Registry</h1>
          <p className="text-xs sm:text-sm font-medium text-ink-muted mt-1">
            Filter, analyze, and inspect unidirectional passive detections in real time.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={handleExport}
            className="px-4 py-2 text-xs font-bold text-forest bg-forest-light hover:bg-forest/15 rounded-full border border-forest-border/50 transition-all duration-200 shadow-2xs flex items-center gap-1.5"
            title="Download currently filtered threat alerts as JSON"
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            {exported ? 'Logs Downloaded ✓' : 'Export Logs'}
          </button>
        </div>
      </div>

      {/* Search & Filters */}
      <AlertFilters
        filters={filters}
        searchQuery={searchQuery}
        onSeverity={setSeverityFilter}
        onThreat={setThreatFilter}
        onTimeRange={setTimeRangeFilter}
        onSearch={setSearchQuery}
        onClear={clearFilters}
      />

      {/* Main Alert Feed Table */}
      <LiveAlertFeed
        alerts={filtered}
        onSelect={openAlert}
        title="Threat Alert Registry"
        maxHeight="max-h-[calc(100vh-320px)]"
      />

      <Outlet />
    </div>
  );
}
