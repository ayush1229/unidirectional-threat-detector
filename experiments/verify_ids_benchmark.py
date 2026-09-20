"""Independent integrity audit of the freshly generated IDS replay corpus."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import struct

import dpkt


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    args = parser.parse_args()
    episodes = json.loads((args.corpus / 'episodes.json').read_text())
    audits = []
    for episode in episodes:
        path = args.corpus / episode['pcap']
        assert sha(path) == episode['sha256']
        pairs = set()
        packets = ip_errors = transport_errors = 0
        with path.open('rb') as stream:
            for _, raw in dpkt.pcap.Reader(stream):
                ip = dpkt.ethernet.Ethernet(raw).data
                pairs.add((socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)))
                ip_errors += dpkt.in_cksum(raw[14:14 + ip.hl * 4]) != 0
                payload = raw[14 + ip.hl * 4:14 + ip.len]
                pseudo = struct.pack('!4s4sBBH', ip.src, ip.dst, 0, ip.p, len(payload))
                transport_errors += dpkt.in_cksum(pseudo + payload) != 0
                packets += 1
        assert packets == episode['packets']
        assert not any((dst, src) in pairs for src, dst in pairs)
        assert ip_errors == transport_errors == 0
        audits.append({'episode_id': episode['episode_id'], 'packets': packets,
                       'reverse_pairs': 0, 'ip_checksum_errors': ip_errors,
                       'transport_checksum_errors': transport_errors})
    model_manifest = json.loads((args.corpus / 'model_manifest.json').read_text())
    project = Path(__file__).resolve().parents[1]
    manifest_path = project / model_manifest['current_pointer']['agent2_release']
    assert sha(manifest_path) == model_manifest['agent2_manifest_sha256']
    for name, expected in model_manifest['agent2_artifacts'].items():
        assert sha(manifest_path.parent / name) == expected
    tools_manifest = {'created_at': datetime.now(timezone.utc).isoformat(),
        'installation': 'User-local dpkg extraction; no system services installed or started',
        'sources': {'Ubuntu': 'http://archive.ubuntu.com/ubuntu',
          'Zeek': 'https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/amd64/zeek-core_9.0.0-0_amd64.deb',
          'Snort Community': 'https://www.snort.org/downloads/community/community-rules.tar.gz',
          'ET Open': 'https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz'},
        'downloads': {p.name: {'bytes': p.stat().st_size, 'sha256': sha(p)}
                      for p in sorted((args.tools / 'packages').iterdir()) if p.is_file()}}
    (args.corpus / 'tool_download_manifest.json').write_text(json.dumps(tools_manifest, indent=2) + '\n')
    result = {'status': 'passed', 'episode_count': len(audits),
              'packet_count': sum(a['packets'] for a in audits),
              'current_agent2_unchanged': True, 'episodes': audits}
    (args.corpus / 'independent_integrity_audit.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'episodes'}))


if __name__ == '__main__':
    main()
