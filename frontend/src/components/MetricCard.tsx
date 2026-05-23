type MetricCardProps = {
  label: string;
  value: string;
  delta: string;
  accent: 'signal' | 'ember' | 'violet' | 'slate';
};

const accentStyles: Record<MetricCardProps['accent'], string> = {
  signal: 'from-signal-400/30 to-signal-500/10 border-signal-400/30',
  ember: 'from-ember-400/30 to-ember-500/10 border-ember-400/30',
  violet: 'from-fuchsia-400/25 to-indigo-500/10 border-fuchsia-400/30',
  slate: 'from-slate-400/20 to-slate-500/10 border-slate-400/20',
};

export function MetricCard({ label, value, delta, accent }: MetricCardProps) {
  return (
    <div className={`rounded-[1.75rem] border bg-gradient-to-br p-5 shadow-glow ${accentStyles[accent]}`}>
      <div className="text-xs font-semibold uppercase tracking-[0.28em] text-slate-300">{label}</div>
      <div className="mt-4 flex items-end justify-between gap-4">
        <div className="text-4xl font-bold tracking-tight text-white">{value}</div>
        <div className="rounded-full border border-white/10 bg-black/20 px-3 py-1 text-xs font-semibold text-slate-200">
          {delta}
        </div>
      </div>
    </div>
  );
}
