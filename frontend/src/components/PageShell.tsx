import type { ReactNode } from 'react';
import type { PageKey } from '../data';
import { navigation } from '../data';

type PageShellProps = {
  activePage: PageKey;
  onNavigate: (page: PageKey) => void;
  children: ReactNode;
};

export function PageShell({ activePage, onNavigate, children }: PageShellProps) {
  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(20,184,166,0.16),_transparent_32%),radial-gradient(circle_at_top_right,_rgba(249,115,22,0.12),_transparent_28%),linear-gradient(180deg,#050816_0%,#081122_52%,#0b1326_100%)] text-slate-50">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -left-32 top-24 h-80 w-80 rounded-full bg-signal-500/20 blur-3xl" />
        <div className="absolute right-0 top-16 h-72 w-72 rounded-full bg-ember-500/15 blur-3xl" />
      </div>
      <div className="relative mx-auto grid min-h-screen max-w-[1600px] grid-cols-1 lg:grid-cols-[300px_1fr]">
        <aside className="border-b border-white/10 bg-white/5 px-5 py-6 backdrop-blur-xl lg:border-b-0 lg:border-r lg:px-6">
          <div className="mb-8 rounded-3xl border border-white/10 bg-white/5 p-5 shadow-glow">
            <p className="text-xs font-semibold uppercase tracking-[0.35em] text-signal-100/90">CloudSpecter</p>
            <h1 className="mt-3 text-3xl font-bold tracking-tight text-white">Startup-grade cloud security dashboard</h1>
            <p className="mt-3 text-sm leading-6 text-slate-300">
              Live posture, attack activity, and downloadable reports in one focused command center.
            </p>
          </div>

          <nav className="space-y-2">
            {navigation.map((item) => {
              const isActive = item.key === activePage;
              return (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => onNavigate(item.key)}
                  className={`flex w-full items-center justify-between rounded-2xl border px-4 py-3 text-left transition duration-200 ${
                    isActive
                      ? 'border-signal-400/60 bg-signal-400/10 text-white shadow-glow'
                      : 'border-white/10 bg-white/5 text-slate-300 hover:border-white/20 hover:bg-white/10 hover:text-white'
                  }`}
                >
                  <span>
                    <span className="block text-sm font-semibold">{item.label}</span>
                    <span className="block text-xs text-slate-400">{item.subtitle}</span>
                  </span>
                  <span className="text-xs uppercase tracking-[0.24em] text-slate-400">{String(item.key).slice(0, 3)}</span>
                </button>
              );
            })}
          </nav>

          <div className="mt-8 rounded-3xl border border-white/10 bg-white/5 p-5 text-sm text-slate-300">
            <p className="text-xs font-semibold uppercase tracking-[0.3em] text-signal-100/90">Status</p>
            <div className="mt-3 flex items-center justify-between">
              <span>Frontend ready</span>
              <span className="rounded-full bg-signal-500/15 px-3 py-1 text-xs font-semibold text-signal-100">Online</span>
            </div>
            <div className="mt-4 grid grid-cols-2 gap-3 text-xs text-slate-400">
              <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
                <div className="font-semibold text-slate-100">React</div>
                <div>SPA shell</div>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/20 p-3">
                <div className="font-semibold text-slate-100">Chart.js</div>
                <div>Inline insights</div>
              </div>
            </div>
          </div>
        </aside>

        <main className="relative px-4 py-5 sm:px-6 lg:px-8 lg:py-6">
          <div className="mb-6 flex flex-col gap-4 rounded-[2rem] border border-white/10 bg-white/5 p-5 backdrop-blur-xl lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.35em] text-signal-100/90">Control room</p>
              <h2 className="mt-2 text-2xl font-bold tracking-tight text-white sm:text-3xl">Cloud posture, attack flow, and report delivery</h2>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
              <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3 text-slate-300">
                <div className="text-xs uppercase tracking-[0.24em] text-slate-400">Region</div>
                <div className="mt-1 font-semibold text-white">us-east-1</div>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3 text-slate-300">
                <div className="text-xs uppercase tracking-[0.24em] text-slate-400">Engine</div>
                <div className="mt-1 font-semibold text-white">Live</div>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3 text-slate-300">
                <div className="text-xs uppercase tracking-[0.24em] text-slate-400">Reports</div>
                <div className="mt-1 font-semibold text-white">PDF-ready</div>
              </div>
              <div className="rounded-2xl border border-white/10 bg-black/20 px-4 py-3 text-slate-300">
                <div className="text-xs uppercase tracking-[0.24em] text-slate-400">Theme</div>
                <div className="mt-1 font-semibold text-white">Startup vibes</div>
              </div>
            </div>
          </div>

          {children}
        </main>
      </div>
    </div>
  );
}
