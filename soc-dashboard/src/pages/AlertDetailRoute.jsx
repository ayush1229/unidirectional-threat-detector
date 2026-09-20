import { useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAlertStore } from '../store/alertStore';
import AlertDetailModal from '../components/alerts/AlertDetailModal';

/**
 * Deep-linkable alert detail. Renders the same drill-down modal used from
 * the dashboard/alerts tables, resolving the alert by flow_id from the
 * store so a direct visit to /alerts/:flowId works as long as that alert
 * is still in the retained alert window.
 */
export default function AlertDetailRoute() {
  const { flowId } = useParams();
  const navigate = useNavigate();
  const selectAlertByFlowId = useAlertStore((s) => s.selectAlertByFlowId);
  const selectedAlert = useAlertStore((s) => s.selectedAlert);
  const clearSelectedAlert = useAlertStore((s) => s.clearSelectedAlert);

  useEffect(() => {
    selectAlertByFlowId(flowId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flowId]);

  function close() {
    clearSelectedAlert();
    navigate(-1);
  }

  if (!selectedAlert) {
    return (
      <div className="mx-auto max-w-lg px-6 py-16 text-center">
        <p className="text-base font-bold text-ink-primary font-sans">Alert Not Found</p>
        <p className="mt-1 text-xs font-medium text-ink-muted">
          Flow <span className="mono font-bold text-forest">{flowId}</span> is not in the currently retained alert window.
        </p>
        <button
          onClick={() => navigate('/alerts')}
          className="mt-5 rounded-full border border-forest-border bg-forest px-4 py-2 text-xs font-bold text-white shadow-sm hover:bg-forest-hover transition-all"
        >
          Back to Alerts Registry
        </button>
      </div>
    );
  }

  return <AlertDetailModal alert={selectedAlert} onClose={close} />;
}
