/**
 * exportUtils.js
 * Utility to export alerts into structured forensic JSON or CSV formats.
 */

export function exportAlertsToJson(alerts, prefix = 'sentinel-threat-alerts') {
  if (!alerts || alerts.length === 0) {
    alert('No alerts currently in memory to export.');
    return;
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `${prefix}-${timestamp}.json`;

  const payload = {
    system: 'SIH26145 AI-Based Unidirectional Threat Detector',
    exported_at: new Date().toISOString(),
    total_records: alerts.length,
    alerts: alerts,
  };

  const jsonStr = JSON.stringify(payload, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export function exportAlertsToCsv(alerts, prefix = 'sentinel-threat-alerts') {
  if (!alerts || alerts.length === 0) {
    alert('No alerts currently in memory to export.');
    return;
  }

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `${prefix}-${timestamp}.csv`;

  const headers = [
    'timestamp',
    'flow_id',
    'severity',
    'threat_class',
    'confidence_score',
    'protocol',
    'src_ip',
    'src_port',
    'dst_ip',
    'dst_port',
    'sensor_id',
    'supervised_score',
    'anomaly_score',
    'sequence_score'
  ];

  const rows = alerts.map(a => [
    `"${a.timestamp || ''}"`,
    `"${a.flow_id || ''}"`,
    `"${a.severity || ''}"`,
    `"${a.threat_class || ''}"`,
    a.confidence_score ?? '',
    `"${a.five_tuple?.protocol || ''}"`,
    `"${a.five_tuple?.src_ip || ''}"`,
    a.five_tuple?.src_port ?? '',
    `"${a.five_tuple?.dst_ip || ''}"`,
    a.five_tuple?.dst_port ?? '',
    `"${a.ingestion_meta?.sensor_id || ''}"`,
    a.model_source?.supervised_score ?? '',
    a.model_source?.anomaly_score ?? '',
    a.model_source?.sequence_score ?? '',
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
