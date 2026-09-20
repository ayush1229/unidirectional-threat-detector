import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import ChartPanel from './ChartPanel';
import EmptyState from '../common/EmptyState';
import { THREAT_CLASSES } from '../../types/alert';
import { threatClassShortLabel, threatClassColor } from '../../utils/threatUtils';

function buildData(alerts) {
  const counts = {};
  for (const a of alerts) counts[a.threat_class] = (counts[a.threat_class] ?? 0) + 1;
  return THREAT_CLASSES
    .filter((c) => counts[c])
    .map((c) => ({ name: threatClassShortLabel(c), value: counts[c], color: threatClassColor(c) }));
}

const TIP_STYLE = {
  background: '#FFFFFF',
  border: '1px solid #E1E8E3',
  borderRadius: '12px',
  boxShadow: '0 4px 20px -2px rgba(11, 79, 48, 0.12)',
  fontSize: 12,
  padding: '8px 12px',
};

export default function ThreatDistributionChart({ alerts }) {
  const data  = buildData(alerts);
  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <ChartPanel title="Threat Distribution" subtitle="Alerts by detected threat class">
      {data.length === 0
        ? <EmptyState title="No classified alerts yet" />
        : (
          <div className="flex items-center gap-6 h-[220px]">
            {/* Donut with Centered Label (Reference B style) */}
            <div className="relative shrink-0 w-[170px] h-full flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data} dataKey="value" nameKey="name"
                    innerRadius={54} outerRadius={76}
                    paddingAngle={3} strokeWidth={0} startAngle={90} endAngle={-270}
                  >
                    {data.map((d) => <Cell key={d.name} fill={d.color} />)}
                  </Pie>
                  <Tooltip
                    contentStyle={TIP_STYLE}
                    itemStyle={{ color: '#1A2E23', fontWeight: 600 }}
                    formatter={(v, n) => [`${v} (${((v/total)*100).toFixed(0)}%)`, n]}
                  />
                </PieChart>
              </ResponsiveContainer>

              {/* Centered label inside donut */}
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="mono text-2xl font-extrabold text-forest leading-none">{total}</span>
                <span className="text-[10px] font-bold text-ink-muted uppercase tracking-wider mt-0.5">Classified</span>
              </div>
            </div>

            {/* Legend */}
            <div className="flex flex-col gap-2 flex-1 min-w-0 pr-2">
              {data.map((d) => (
                <div key={d.name} className="flex items-center justify-between gap-3 p-1.5 rounded-lg hover:bg-surface-2 transition-colors">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="h-2.5 w-2.5 shrink-0 rounded-full shadow-2xs" style={{ background: d.color }} />
                    <span className="text-xs font-semibold text-ink-primary truncate">{d.name}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-xs font-bold text-ink-primary mono">{d.value}</span>
                    <span className="text-2xs font-medium text-ink-muted w-9 text-right bg-surface-2 px-1.5 py-0.5 rounded">
                      {((d.value / total) * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
    </ChartPanel>
  );
}
