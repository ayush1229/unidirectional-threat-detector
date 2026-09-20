/**
 * Standardized JSON Alert contract — SIH26145.
 *
 * This module is the single source of truth for the shape of an alert as it
 * crosses the Backend → WebSocket → Frontend boundary. Nothing downstream of
 * this file should invent, rename, or silently coerce fields — if the
 * backend contract changes, change it here first.
 *
 * Written as JSDoc typedefs so editors get real autocomplete/type-checking
 * in a plain-JS (non-TypeScript) project, per project constraints.
 */

/**
 * @typedef {'VOLUMETRIC_DDOS'|'PORT_SCAN'|'DATA_EXFILTRATION'|'DGA_DOMAIN'|'DNS_TUNNELING'|'BOTNET_C2_BEACONING'|'MALWARE_ENCRYPTED_TLS'|'ANOMALOUS_UNCLASSIFIED'} ThreatClass
 */

/**
 * @typedef {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'} Severity
 */

/**
 * @typedef {Object} FiveTuple
 * @property {string} src_ip
 * @property {string} dst_ip
 * @property {number} src_port
 * @property {number} dst_port
 * @property {string} protocol
 */

/**
 * @typedef {Object} ModelSource
 * @property {number} supervised_score
 * @property {number} anomaly_score
 * @property {number} sequence_score
 * @property {string[]} fired_models
 */

/**
 * Evidence is intentionally an open bag of fields — different threat classes
 * surface different evidence (e.g. beacon_interval_seconds for C2 beaconing,
 * packet-per-second fan-out for a port scan). The UI must render whatever is
 * present without hardcoding a field list per threat class.
 * @typedef {Object.<string, string|number|boolean|number[]>} Evidence
 */

/**
 * @typedef {Object} IngestionMeta
 * @property {string} sensor_id
 * @property {string} capture_interface
 * @property {string} pipeline_version
 */

/**
 * @typedef {Object} Alert
 * @property {string} timestamp        ISO-8601
 * @property {string} flow_id          UUID
 * @property {FiveTuple} five_tuple
 * @property {ThreatClass} threat_class
 * @property {number} confidence_score 0..1
 * @property {Severity} severity
 * @property {ModelSource} model_source
 * @property {Evidence} evidence
 * @property {IngestionMeta} ingestion_meta
 */

export const THREAT_CLASSES = /** @type {const} */ ([
  'DDoS', 'DGA', 'DNS_TUNNEL', 'C2_BEACONING', 'BOTNET_HOST',
  'BOTNET_COORDINATION', 'ENCRYPTED_MALWARE', 'UNCERTAIN',
  'BRUTE_FORCE', 'WEB_ATTACK', 'UNKNOWN',
  'VOLUMETRIC_DDOS',
  'PORT_SCAN',
  'DATA_EXFILTRATION',
  'DGA_DOMAIN',
  'DNS_TUNNELING',
  'BOTNET_C2_BEACONING',
  'MALWARE_ENCRYPTED_TLS',
  'ANOMALOUS_UNCLASSIFIED',
  'BENIGN',
]);

const THREAT_CLASS_MAP = {
  DGA: 'DGA_DOMAIN',
  DGA_DOMAIN: 'DGA_DOMAIN',
  DNS_TUNNEL: 'DNS_TUNNELING',
  DNS_TUNNELING: 'DNS_TUNNELING',
  DDOS: 'VOLUMETRIC_DDOS',
  VOLUMETRIC_DDOS: 'VOLUMETRIC_DDOS',
  SCAN: 'PORT_SCAN',
  PORT_SCAN: 'PORT_SCAN',
  EXFIL: 'DATA_EXFILTRATION',
  DATA_EXFILTRATION: 'DATA_EXFILTRATION',
  C2: 'BOTNET_C2_BEACONING',
  BOTNET_C2: 'BOTNET_C2_BEACONING',
  BOTNET_C2_BEACONING: 'BOTNET_C2_BEACONING',
  MALWARE_ENCRYPTED_TLS: 'MALWARE_ENCRYPTED_TLS',
  MALWARE_TLS: 'MALWARE_ENCRYPTED_TLS',
  ANOMALOUS: 'ANOMALOUS_UNCLASSIFIED',
  ANOMALOUS_UNCLASSIFIED: 'ANOMALOUS_UNCLASSIFIED',
  BENIGN: 'BENIGN',
};

export const SEVERITIES = /** @type {const} */ (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

/** WebSocket / pipeline connection states shown in the UI. Never faked. */
export const CONNECTION_STATES = /** @type {const} */ ([
  'CONNECTED',
  'CONNECTING',
  'DISCONNECTED',
  'RECONNECTING',
]);

/**
 * Runtime shape check for a message arriving off the wire. Does not throw —
 * returns null for anything that doesn't satisfy the contract so the caller
 * can drop malformed messages instead of crashing the dashboard.
 * @param {any} raw
 * @returns {Alert|null}
 */
export function normalizeAlert(raw) {
  if (!raw || typeof raw !== 'object') return null;
  if (raw.schema_version === '2.0.0') {
    if (!raw.decision_id || !raw.entity_keys || !['BENIGN', 'KNOWN_ATTACK', 'UNKNOWN', 'UNCERTAIN'].includes(raw.decision_state)) return null;
    if (!raw.labels || !raw.uncertainty || !raw.model_versions || !raw.event_time) return null;
    return {
      ...raw,
      flow_id: raw.decision_id,
      timestamp: raw.event_time,
      threat_class: raw.primary_class || raw.decision_state,
      confidence_score: typeof raw.confidence === 'number' && Number.isFinite(raw.confidence) ? raw.confidence : null,
      severity: SEVERITIES.includes(raw.severity) ? raw.severity : raw.decision_state === 'UNCERTAIN' || raw.decision_state === 'BENIGN' ? 'LOW' : raw.confidence >= .9 ? 'CRITICAL' : 'HIGH',
      five_tuple: { src_ip: raw.entity_keys.source, dst_ip: raw.entity_keys.destination, src_port: null, dst_port: null, protocol: raw.protocol },
      model_source: { supervised_score: null, anomaly_score: null, sequence_score: null, fired_models: Object.keys(raw.model_versions) },
      ingestion_meta: { sensor_id: raw.sensor_id, capture_interface: null, pipeline_version: raw.schema_version },
    };
  }
  if (!raw.flow_id && !raw._id) return null;
  if (!raw.threat_class || !raw.five_tuple) return null;

  // Map threat class aliases (e.g. DGA -> DGA_DOMAIN, DNS_TUNNEL -> DNS_TUNNELING)
  const rawClass = String(raw.threat_class || '').toUpperCase().trim();
  const threat_class = THREAT_CLASS_MAP[rawClass] || (THREAT_CLASSES.includes(rawClass) ? rawClass : 'ANOMALOUS_UNCLASSIFIED');

  // Normalize severity
  const rawSev = String(raw.severity || '').toUpperCase().trim();
  const severity = SEVERITIES.includes(rawSev) ? rawSev : 'HIGH';

  const flow_id = raw.flow_id || raw._id || ('flow-' + Math.random().toString(36).substring(2, 9));
  const timestamp = raw.timestamp || raw.createdAt || raw.ts || new Date().toISOString();

  const rawTuple = raw.five_tuple || {};
  const five_tuple = {
    src_ip: rawTuple.src_ip ?? 'unknown',
    dst_ip: rawTuple.dst_ip ?? 'unknown',
    src_port: Number(rawTuple.src_port) || 0,
    dst_port: Number(rawTuple.dst_port) || 0,
    protocol: rawTuple.protocol ?? 'TCP',
  };

  return {
    timestamp,
    flow_id,
    five_tuple,
    threat_class,
    confidence_score: typeof raw.confidence_score === 'number' ? raw.confidence_score : null,
    severity,
    model_source: {
      supervised_score: raw.model_source?.supervised_score ?? null,
      anomaly_score: raw.model_source?.anomaly_score ?? null,
      sequence_score: raw.model_source?.sequence_score ?? null,
      fired_models: raw.model_source?.fired_models ?? [],
    },
    evidence: raw.evidence ?? {},
    ingestion_meta: {
      sensor_id: raw.ingestion_meta?.sensor_id ?? 'diode-sensor-01',
      capture_interface: raw.ingestion_meta?.capture_interface ?? 'lo',
      pipeline_version: raw.ingestion_meta?.pipeline_version ?? '1.0.0',
    },
  };
}
