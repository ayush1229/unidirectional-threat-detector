$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Split-Path -Parent $root)

Write-Host '== Agent 1: pytest ==' -ForegroundColor Cyan
python -m pytest agent1_observation_dns/tests -q -p no:cacheprovider

Write-Host '== Agent 1: compile check ==' -ForegroundColor Cyan
python -m compileall -q agent1_observation_dns

Write-Host '== Agent 1: contract schema check ==' -ForegroundColor Cyan
python -c "import json; from pathlib import Path; p=Path('agent1_observation_dns/contracts'); v=[json.loads((p/x/'schema.json').read_text())['properties']['schema_version'].get('const') for x in ('observation','specialist_score','scenario_release')]; assert v == ['2.0.0','2.0.0','1.0.0'], v; print('schemas:', ', '.join(v))"

Write-Host '== Agent 1: offline replay smoke test ==' -ForegroundColor Cyan
$smoke = Join-Path $root 'artifacts/test-tmp'
New-Item -ItemType Directory -Force $smoke | Out-Null
$output = Join-Path $smoke 'replay.jsonl'
Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue
python -m agent1_observation_dns replay agent1_observation_dns/tests/golden/dns_tcp.pcap $output
$lines = @(Get-Content -LiteralPath $output).Count
if ($lines -lt 1) { throw 'Replay produced no observations' }
Remove-Item -LiteralPath $smoke -Recurse -Force
Write-Host "Replay records: $lines" -ForegroundColor Green
Write-Host 'Agent 1 checks passed.' -ForegroundColor Green
