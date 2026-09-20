export default function ChartPanel({ title, subtitle, children, action }) {
  return (
    <div className="card flex flex-col overflow-hidden transition-all duration-200">
      <div className="flex items-center justify-between px-5 py-4 border-b border-border/70 bg-surface-0/50">
        <div>
          <h3 className="text-sm font-bold font-sans text-ink-primary tracking-tight">{title}</h3>
          {subtitle && <p className="text-2xs font-medium text-ink-muted mt-0.5">{subtitle}</p>}
        </div>
        {action}
      </div>
      <div className="p-5 flex-1">{children}</div>
    </div>
  );
}
