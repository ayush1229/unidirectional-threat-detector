/**
 * REST API Client for Person 4 Backend Service.
 * Exposes methods to fetch paginated alerts, historical searches, single alert details, and pipeline health.
 */
import { normalizeAlert } from '../types/alert';
import { API_BASE as API_BASE_URL } from './config';


/**
 * Fetch paginated list of alerts (newest first)
 * @param {Object} options { page, limit }
 */
export async function fetchAlerts({ page = 1, limit = 50 } = {}) {
  try {
    const res = await fetch(`${API_BASE_URL}/alerts?page=${page}&limit=${limit}`);
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    const json = await res.json();
    
    if (json.status === 'success' && json.data && Array.isArray(json.data.alerts)) {
      const normalized = json.data.alerts
        .map(a => normalizeAlert(a))
        .filter(Boolean);
      return {
        alerts: normalized,
        total: json.data.total,
        page: json.data.page,
        totalPages: json.data.totalPages
      };
    }
    return { alerts: [], total: 0, page: 1, totalPages: 1 };
  } catch (err) {
    console.warn('[API Client] Failed to fetch alerts from backend:', err.message);
    return null;
  }
}

/**
 * Fetch single alert by flow_id
 * @param {string} flowId 
 */
export async function fetchAlertByFlowId(flowId) {
  try {
    const res = await fetch(`${API_BASE_URL}/alerts/${encodeURIComponent(flowId)}`);
    if (!res.ok) return null;
    const json = await res.json();
    if (json.status === 'success' && json.data) {
      return normalizeAlert(json.data);
    }
    return null;
  } catch (err) {
    console.warn(`[API Client] Failed to fetch alert detail for ${flowId}:`, err.message);
    return null;
  }
}

/**
 * Search historical alerts with filters
 * @param {Object} params { threat_class, severity, from, to, page, limit }
 */
export async function searchAlerts(params = {}) {
  try {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null && val !== '') {
        query.append(key, val);
      }
    });

    const res = await fetch(`${API_BASE_URL}/alerts/search?${query.toString()}`);
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    const json = await res.json();

    if (json.status === 'success' && json.data && Array.isArray(json.data.alerts)) {
      const normalized = json.data.alerts
        .map(a => normalizeAlert(a))
        .filter(Boolean);
      return {
        alerts: normalized,
        total: json.data.total,
        page: json.data.page,
        totalPages: json.data.totalPages
      };
    }
    return { alerts: [], total: 0, page: 1, totalPages: 1 };
  } catch (err) {
    console.warn('[API Client] Failed to search historical alerts:', err.message);
    return null;
  }
}

/**
 * Fetch health status of pipeline backend
 */
export async function fetchHealth() {
  try {
    const res = await fetch(`${API_BASE_URL}/health`);
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API Client] Health check failed:', err.message);
    return null;
  }
}
