/**
 * Realistic mock alerts, structurally identical to the backend's standardized
 * JSON contract (see src/types/alert.js). Used when VITE_USE_MOCK_DATA=true,
 * and as the seed data for Live Demo Mode.
 *
 * These are illustrative sample values only — not derived from any real
 * capture — and exist purely so the dashboard is fully exercisable before
 * Person 4's backend is reachable.
 */

function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function isoNow(offsetSeconds = 0) {
  return new Date(Date.now() + offsetSeconds * 1000).toISOString();
}

const SENSORS = ['diode-sensor-01', 'diode-sensor-02', 'diode-sensor-04'];

function baseIngestionMeta(overrides = {}) {
  return {
    sensor_id: SENSORS[Math.floor(Math.random() * SENSORS.length)],
    capture_interface: 'eth1-rx-only',
    pipeline_version: '1.3.0',
    ...overrides,
  };
}

/** @returns {import('../types/alert').Alert} */
export function makeVolumetricDdosAlert(offsetSeconds = 0) {
  return {
    timestamp: isoNow(offsetSeconds),
    flow_id: uuid(),
    five_tuple: {
      src_ip: `203.0.113.${Math.floor(Math.random() * 254) + 1}`,
      dst_ip: '198.51.100.10',
      src_port: Math.floor(Math.random() * 60000) + 1024,
      dst_port: 443,
      protocol: 'UDP',
    },
    threat_class: 'VOLUMETRIC_DDOS',
    confidence_score: 0.97,
    severity: 'CRITICAL',
    model_source: {
      supervised_score: 0.98,
      anomaly_score: 0.91,
      sequence_score: 0.4,
      fired_models: ['xgb_volumetric_v3', 'isolation_forest_v3'],
    },
    evidence: {
      packets_per_second: 48210,
      bytes_out_total: 512000000,
      unique_dst_ips: 1,
      asymmetric_byte_ratio: 0.99,
      src_ip_entropy: 0.87,
    },
    ingestion_meta: baseIngestionMeta(),
  };
}

export function makePortScanAlert(offsetSeconds = 0) {
  return {
    timestamp: isoNow(offsetSeconds),
    flow_id: uuid(),
    five_tuple: {
      src_ip: `10.44.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`,
      dst_ip: '198.51.100.23',
      src_port: Math.floor(Math.random() * 60000) + 1024,
      dst_port: 22,
      protocol: 'TCP',
    },
    threat_class: 'PORT_SCAN',
    confidence_score: 0.89,
    severity: 'MEDIUM',
    model_source: {
      supervised_score: 0.86,
      anomaly_score: 0.52,
      sequence_score: 0.1,
      fired_models: ['xgb_scan_v2'],
    },
    evidence: {
      unique_dst_ports: 1342,
      syn_ratio: 0.98,
      packets_per_second: 910,
      ttl_variance: 0.02,
    },
    ingestion_meta: baseIngestionMeta(),
  };
}

export function makeDataExfiltrationAlert(offsetSeconds = 0) {
  return {
    timestamp: isoNow(offsetSeconds),
    flow_id: uuid(),
    five_tuple: {
      src_ip: `10.44.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`,
      dst_ip: '203.0.113.77',
      src_port: Math.floor(Math.random() * 60000) + 1024,
      dst_port: 443,
      protocol: 'TCP/TLS',
    },
    threat_class: 'DATA_EXFILTRATION',
    confidence_score: 0.91,
    severity: 'HIGH',
    model_source: {
      supervised_score: 0.83,
      anomaly_score: 0.79,
      sequence_score: 0.35,
      fired_models: ['xgb_exfil_v2', 'autoencoder_v1'],
    },
    evidence: {
      bytes_out_total: 812345678,
      bytes_in_total: 210044,
      asymmetric_byte_ratio: 0.97,
      ja3_fingerprint: '72a589da586844d7f0818ce684948eea',
    },
    ingestion_meta: baseIngestionMeta(),
  };
}

export function makeDgaDomainAlert(offsetSeconds = 0) {
  return {
    timestamp: isoNow(offsetSeconds),
    flow_id: uuid(),
    five_tuple: {
      src_ip: `10.44.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`,
      dst_ip: '198.51.100.53',
      src_port: Math.floor(Math.random() * 60000) + 1024,
      dst_port: 53,
      protocol: 'UDP/DNS',
    },
    threat_class: 'DGA_DOMAIN',
    confidence_score: 0.84,
    severity: 'MEDIUM',
    model_source: {
      supervised_score: 0.81,
      anomaly_score: 0.44,
      sequence_score: 0.05,
      fired_models: ['dga_ngram_classifier_v2'],
    },
    evidence: {
      query_entropy: 4.31,
      ngram_score: 0.88,
      distinct_subdomains: 214,
      query_length_mean: 27.4,
    },
    ingestion_meta: baseIngestionMeta(),
  };
}

export function makeDnsTunnelingAlert(offsetSeconds = 0) {
  return {
    timestamp: isoNow(offsetSeconds),
    flow_id: uuid(),
    five_tuple: {
      src_ip: `10.44.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`,
      dst_ip: '198.51.100.53',
      src_port: Math.floor(Math.random() * 60000) + 1024,
      dst_port: 53,
      protocol: 'UDP/DNS',
    },
    threat_class: 'DNS_TUNNELING',
    confidence_score: 0.88,
    severity: 'HIGH',
    model_source: {
      supervised_score: 0.72,
      anomaly_score: 0.85,
      sequence_score: 0.61,
      fired_models: ['dga_ngram_classifier_v2', 'isolation_forest_v3'],
    },
    evidence: {
      query_entropy: 5.02,
      distinct_subdomains: 3980,
      bytes_out_total: 41200000,
      query_length_mean: 61.8,
    },
    ingestion_meta: baseIngestionMeta(),
  };
}

export function makeBotnetC2Alert(offsetSeconds = 0) {
  return {
    timestamp: isoNow(offsetSeconds),
    flow_id: uuid(),
    five_tuple: {
      src_ip: `10.44.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`,
      dst_ip: '198.51.100.23',
      src_port: Math.floor(Math.random() * 60000) + 1024,
      dst_port: 443,
      protocol: 'TCP/TLS',
    },
    threat_class: 'BOTNET_C2_BEACONING',
    confidence_score: 0.93,
    severity: 'HIGH',
    model_source: {
      supervised_score: 0.41,
      anomaly_score: 0.88,
      sequence_score: 0.95,
      fired_models: ['lstm_beacon_v2', 'isolation_forest_v3'],
    },
    evidence: {
      ja3_fingerprint: '6734f37431670b3ab4292b8f60f29984',
      ja4_fingerprint: 't13d1516h2_8daaf6152771_02713d6af862',
      beacon_interval_seconds: 59.8,
      beacon_interval_jitter: 0.6,
      packet_size_sequence_sample: [74, 74, 512, 74, 74, 498],
      src_ip_entropy: 0.11,
      asymmetric_byte_ratio: 0.94,
      cipher_suite_order_anomaly: true,
    },
    ingestion_meta: baseIngestionMeta({ sensor_id: 'diode-sensor-04' }),
  };
}

export function makeAnomalousAlert(offsetSeconds = 0) {
  return {
    timestamp: isoNow(offsetSeconds),
    flow_id: uuid(),
    five_tuple: {
      src_ip: `10.44.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`,
      dst_ip: `203.0.113.${Math.floor(Math.random() * 254) + 1}`,
      src_port: Math.floor(Math.random() * 60000) + 1024,
      dst_port: 8443,
      protocol: 'TCP',
    },
    threat_class: 'ANOMALOUS_UNCLASSIFIED',
    confidence_score: 0.68,
    severity: 'LOW',
    model_source: {
      supervised_score: 0.12,
      anomaly_score: 0.74,
      sequence_score: 0.3,
      fired_models: ['autoencoder_v1'],
    },
    evidence: {
      src_ip_entropy: 0.52,
      asymmetric_byte_ratio: 0.61,
      packets_per_second: 33,
    },
    ingestion_meta: baseIngestionMeta(),
  };
}

export function makeMalwareEncryptedTlsAlert(offsetSeconds = 0) {
  const malwareJa3 = [
    '72a589da586844d7f0818ce684948eea',  // Metasploit Meterpreter
    'a0e9f5d64349fb13191bc781f81f42e1',  // CobaltStrike default
    '6734f37431670b3ab4292b8f60f29984',  // Emotet loader
  ][Math.floor(Math.random() * 3)];
  return {
    timestamp: isoNow(offsetSeconds),
    flow_id: uuid(),
    five_tuple: {
      src_ip: `10.0.${Math.floor(Math.random() * 9) + 1}.${Math.floor(Math.random() * 254) + 1}`,
      dst_ip: `185.${Math.floor(Math.random() * 55) + 200}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`,
      src_port: Math.floor(Math.random() * 16383) + 49152,
      dst_port: [443, 8443, 4443][Math.floor(Math.random() * 3)],
      protocol: 'TCP/TLS',
    },
    threat_class: 'MALWARE_ENCRYPTED_TLS',
    confidence_score: 0.82,
    severity: 'HIGH',
    model_source: {
      supervised_score: 0.15,
      anomaly_score: 0.73,
      sequence_score: 0.18,
      fired_models: ['malware_tls_heuristic', 'anomaly'],
    },
    evidence: {
      ja3_fingerprint: malwareJa3,
      ja4_fingerprint: 't13d190900_' + malwareJa3.slice(0, 12),
      tls_sni: null,
      malware_tls_indicator: 'ja3_in_known_malware_set',
      packets_per_second: Math.floor(Math.random() * 40) + 8,
      bytes_in: Math.floor(Math.random() * 8000) + 1200,
      anomaly_indicator: 'unsupervised_deviation_from_benign_baseline',
      cipher_suite_order_anomaly: true,
    },
    ingestion_meta: baseIngestionMeta(),
  };
}

export const MOCK_ALERT_GENERATORS = [
  makeVolumetricDdosAlert,
  makePortScanAlert,
  makeDataExfiltrationAlert,
  makeDgaDomainAlert,
  makeDnsTunnelingAlert,
  makeBotnetC2Alert,
  makeMalwareEncryptedTlsAlert,
  makeAnomalousAlert,
];

/** A static, structurally-valid seed set covering every threat class. */
export function generateSeedAlerts() {
  return MOCK_ALERT_GENERATORS.map((fn, i) => fn(-1 * (MOCK_ALERT_GENERATORS.length - i) * 47));
}

/** One random alert, for the ambient mock-mode WebSocket simulator. */
export function generateRandomAlert() {
  const fn = MOCK_ALERT_GENERATORS[Math.floor(Math.random() * MOCK_ALERT_GENERATORS.length)];
  return fn();
}
