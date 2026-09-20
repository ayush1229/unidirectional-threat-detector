import { Routes, Route, Navigate, Outlet } from 'react-router-dom';
import Header from './components/layout/Header';
import NavTabs from './components/layout/NavTabs';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import AlertDetailRoute from './pages/AlertDetailRoute';
import { useAlertStore } from './store/alertStore';
import { useWebSocket } from './hooks/useWebSocket';

function AppShell() {
  const connectionStatus = useAlertStore((s) => s.connectionStatus);
  const alerts = useAlertStore((s) => s.alerts);
  const latestAlert = alerts[0];

  useWebSocket();

  return (
    <div className="min-h-screen bg-canvas flex justify-center items-start selection:bg-forest-light selection:text-forest">
      {/* Floating Main Content Panel (Ref B floating style + Ref A light minimal SaaS) */}
      <div className="w-full max-w-[1680px] bg-surface-0 overflow-hidden flex flex-col min-h-[calc(100vh-2.5rem)]">
        <Header
          connectionStatus={connectionStatus}
          latestAlert={latestAlert}
          sensorId={latestAlert?.ingestion_meta?.sensor_id}
          pipelineVersion={latestAlert?.ingestion_meta?.pipeline_version}
        />
        <NavTabs />
        <main className="flex-1 overflow-x-hidden">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/alerts" element={<Alerts />}>
          <Route path=":flowId" element={<AlertDetailRoute />} />
        </Route>
      </Route>
    </Routes>
  );
}
