import { useState } from 'react';
import type { PageKey } from './data';
import { PageShell } from './components/PageShell';
import { OverviewPage } from './pages/OverviewPage';
import { FindingsPage } from './pages/FindingsPage';
import { AssetsPage } from './pages/AssetsPage';
import { ExploitationPage } from './pages/ExploitationPage';
import { ReportsPage } from './pages/ReportsPage';

const pageTitles: Record<PageKey, string> = {
  overview: 'Overview',
  findings: 'Findings',
  assets: 'Assets',
  exploitation: 'Exploitation',
  reports: 'Reports',
};

export default function App() {
  const [activePage, setActivePage] = useState<PageKey>('overview');

  return (
    <PageShell activePage={activePage} onNavigate={setActivePage}>
      <div className="mb-5 flex items-center gap-3 text-xs font-semibold uppercase tracking-[0.3em] text-slate-400">
        <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-signal-100">{pageTitles[activePage]}</span>
        <span>Startup control surface</span>
      </div>

      {activePage === 'overview' && <OverviewPage />}
      {activePage === 'findings' && <FindingsPage />}
      {activePage === 'assets' && <AssetsPage />}
      {activePage === 'exploitation' && <ExploitationPage />}
      {activePage === 'reports' && <ReportsPage />}
    </PageShell>
  );
}
