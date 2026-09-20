import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';

function buildSeries(alerts) {
  const BUCKET_MS = 60_000;
  const BUCKETS   = 30;
  const now        = Date.now();
  const buckets    = Array.from({ length: BUCKETS }, (_, i) => ({
    t:     now - (BUCKETS - 1 - i) * BUCKET_MS,
    count: 0,
  }));
  for (const a of alerts) {
    const age = now - new Date(a.timestamp).getTime();
    if (age < 0 || age > BUCKETS * BUCKET_MS) continue;
    const idx = BUCKETS - 1 - Math.floor(age / BUCKET_MS);
    if (buckets[idx]) buckets[idx].count += 1;
  }
  return buckets.map((b) => ({
    t:     new Date(b.t).toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit' }),
    count: b.count,
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

export default function ThreatActivityChart({ alerts }) {
  const data        = buildSeries(alerts);
  const hasActivity = data.some((d) => d.count > 0);

  return (
    <ChartPanel title="Threat Activity" subtitle="Detections per minute · last 30 min">
      {!hasActivity
        ? <EmptyState title="No activity yet" description="Detections appear here as alerts arrive." />
        : (
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -24, bottom: 0 }}>
              <defs>
                <linearGradient id="grad-activity" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10B981" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#10B981" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#EEF3F0" strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="t"
                tick={{ fill: '#7A9183', fontSize: 10, fontFamily: 'Inter' }}
                axisLine={false} tickLine={false} interval={5}
              />
              <YAxis
                allowDecimals={false}
                tick={{ fill: '#7A9183', fontSize: 10, fontFamily: 'Inter' }}
                axisLine={false} tickLine={false} width={22}
              />
              <Tooltip
                contentStyle={TIP_STYLE}
                labelStyle={{ color: '#496052', fontWeight: 600, marginBottom: 2 }}
                itemStyle={{ color: '#0B4F30', fontWeight: 700 }}
                formatter={(v) => [`${v} detections`, '']}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#0B4F30"
                strokeWidth={2.5}
                fill="url(#grad-activity)"
                dot={false}
                activeDot={{ r: 5, fill: '#10B981', stroke: '#FFFFFF', strokeWidth: 2 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
    </ChartPanel>
  );
}
