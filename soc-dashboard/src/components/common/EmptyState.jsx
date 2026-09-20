export default function EmptyState({ title, description }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2.5 py-12 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-forest-light/60 text-forest border border-forest-border/40 mb-1">
        <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2zm0 0V9a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v10m-6 0a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2m0 0V5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-2a2 2 0 0 1-2-2z" />
        </svg>
      </div>
      <p className="text-sm font-semibold text-ink-primary font-sans">{title}</p>
      {description && <p className="text-xs text-ink-muted max-w-xs leading-relaxed font-medium">{description}</p>}
    </div>
  );
}
