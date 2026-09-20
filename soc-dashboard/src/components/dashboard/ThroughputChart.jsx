import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';
import { usePipelineStats } from '../../hooks/usePipelineStats';

function buildData(alerts) {
  return alerts
    .filter((a) => a.evidence?.packets_per_second != null)
    .slice(0, 15)
    .reverse()
    .map((a) => ({
      t:   new Date(a.timestamp).toLocaleTimeString(undefined, { hour12: false, minute: '2-digit', second: '2-digit' }),
      pps: a.evidence.packets_per_second,
    }));
}

const TIP_STYLE = {
  background: '#FFFFFF',
  border: '1px solid #E1E8E3',
  borderRadius: '12px',
  boxShadow: '0 4px 20px -2px rgba(11, 79, 48, 0.12)',
  fontSize: 12,
  padding: '8px 12px',
};

export default function ThroughputChart({ alerts }) {
  const data = buildData(alerts);
  const { flowsPerSec, throughputWindow } = usePipelineStats();

  const subtitle = flowsPerSec !== null
    ? `${flowsPerSec.toFixed(1)} flows/sec (${throughputWindow == null ? 'run average' : `${throughputWindow}s window`}) · packets/sec on flagged flows`
    : 'Packets / second on flagged flows';

  return (
    <ChartPanel title="Traffic Throughput" subtitle={subtitle}>
      {/* Live flows/sec badge */}
      {flowsPerSec !== null && (
        <div className="flex items-center gap-2 px-1 pb-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 px-2.5 py-0.5 text-xs font-semibold text-blue-400">
            <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulseDot" />
            {flowsPerSec.toFixed(2)} flows / sec
          </span>
        </div>
      )}

      {data.length === 0
        ? <EmptyState title="No per-alert throughput data yet" description="Populated from evidence.packets_per_second as alerts arrive." />
        : (
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={data} margin={{ top: 10, right: 10, left: -24, bottom: 0 }}>
              <CartesianGrid stroke="#EEF3F0" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="t" tick={{ fill: '#7A9183', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#7A9183', fontSize: 10 }} axisLine={false} tickLine={false} width={30} />
              <Tooltip
                contentStyle={TIP_STYLE}
                labelStyle={{ color: '#496052', fontWeight: 600, marginBottom: 2 }}
                itemStyle={{ color: '#0B4F30', fontWeight: 700 }}
                formatter={(v) => [`${v} pps`, '']}
                cursor={{ fill: 'rgba(232, 245, 238, 0.6)' }}
              />
              <Bar dataKey="pps" fill="#0B4F30" radius={[8, 8, 0, 0]} maxBarSize={22} />
            </BarChart>
          </ResponsiveContainer>
        )}
    </ChartPanel>
  );
}
