import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';

function buildData(alerts) {
  return alerts
    .filter((a) => a.evidence?.src_ip_entropy != null)
    .slice(0, 20)
    .reverse()
    .map((a) => ({
      t:       new Date(a.timestamp).toLocaleTimeString(undefined, { hour12: false, minute: '2-digit', second: '2-digit' }),
      entropy: parseFloat(a.evidence.src_ip_entropy.toFixed(3)),
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

export default function EntropyChart({ alerts }) {
  const data = buildData(alerts);
  return (
    <ChartPanel title="IP Entropy Trend" subtitle="Source-IP entropy — higher = more anomalous">
      {data.length === 0
        ? <EmptyState title="No entropy data yet" description="Populated from evidence.src_ip_entropy." />
        : (
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={data} margin={{ top: 10, right: 10, left: -24, bottom: 0 }}>
              <CartesianGrid stroke="#EEF3F0" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="t" tick={{ fill: '#7A9183', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 1]} tick={{ fill: '#7A9183', fontSize: 10 }} axisLine={false} tickLine={false} width={22} />
              <ReferenceLine y={0.7} stroke="#DC2626" strokeDasharray="3 5" strokeOpacity={0.6} label={false} />
              <Tooltip
                contentStyle={TIP_STYLE}
                labelStyle={{ color: '#496052', fontWeight: 600, marginBottom: 2 }}
                itemStyle={{ color: '#D97706', fontWeight: 700 }}
                formatter={(v) => [v, 'entropy']}
                cursor={{ stroke: '#CBD5CE' }}
              />
              <Line
                type="monotone" dataKey="entropy"
                stroke="#D97706" strokeWidth={2.5}
                dot={{ r: 3, fill: '#D97706', strokeWidth: 0 }}
                activeDot={{ r: 5, fill: '#D97706', stroke: '#FFFFFF', strokeWidth: 2 }}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
    </ChartPanel>
  );
}
