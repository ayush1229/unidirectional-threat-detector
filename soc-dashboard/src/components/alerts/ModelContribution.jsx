import ScoreBar from '../common/ScoreBar';

export default function ModelContribution({ modelSource }) {
  if (!modelSource) return null;

  return (
    <div className="space-y-4">
      <div className="space-y-3.5 rounded-2xl border border-border/70 bg-surface-2/60 p-4 shadow-2xs">
        <ScoreBar label="Supervised Model (XGBoost)" value={modelSource.supervised_score} color="#0B4F30" />
        <ScoreBar label="Anomaly Detection (IsoForest / AE)" value={modelSource.anomaly_score} color="#D97706" />
        <ScoreBar label="Sequential Deep Learning (LSTM)" value={modelSource.sequence_score} color="#10B981" />
      </div>

      {modelSource.fired_models?.length > 0 && (
        <div>
          <span className="text-2xs font-bold uppercase tracking-wider text-ink-muted">Fired Models</span>
          <div className="mt-2 flex flex-wrap gap-2">
            {modelSource.fired_models.map((m) => (
              <span
                key={m}
                className="rounded-full border border-forest-border/40 bg-forest-light px-3 py-1 mono text-[11px] font-bold text-forest shadow-2xs"
              >
                {m}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
