import React, { useEffect, useState } from 'react';
import { kpis as staticKpis, findings as staticFindings, assets as staticAssets, attackEvents as staticAttackEvents, Kpi, Finding, Asset, AttackEvent } from '../data';
import { MetricCard } from '../components/MetricCard';
import { ChartCard, SeverityDoughnut, AttackTimeline } from '../components/Charts';
import { fetchKpis, fetchFindings, fetchAssets, fetchAttackEvents, runAwsAudit } from '../api';

export function OverviewPage() {
  const [kpis, setKpis] = useState<Kpi[]>(staticKpis);
  const [findings, setFindings] = useState<Finding[]>(staticFindings);
  const [assets, setAssets] = useState<Asset[]>(staticAssets);
  const [attackEvents, setAttackEvents] = useState<AttackEvent[]>(staticAttackEvents);

  useEffect(() => {
    fetchKpis().then((d) => setKpis(d)).catch(() => undefined);
    fetchFindings().then((d) => setFindings(d)).catch(() => undefined);
    fetchAssets().then((d) => setAssets(d)).catch(() => undefined);
    fetchAttackEvents().then((d) => setAttackEvents(d)).catch(() => undefined);
  }, []);

  // audit form state
  const [endpoint, setEndpoint] = useState('');
  const [region, setRegion] = useState('us-east-1');
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [lastAuditMsg, setLastAuditMsg] = useState<string | null>(null);

  async function handleRunAudit(e?: React.FormEvent) {
    e?.preventDefault();
    setLoadingAudit(true);
    setLastAuditMsg(null);
    try {
      const report = await runAwsAudit(endpoint || undefined, region || undefined);
      const newFindings = report.findings || [];
      setFindings(newFindings);
      setLastAuditMsg(`Audit complete — ${newFindings.length} findings`);
    } catch (err: any) {
      setLastAuditMsg(`Audit failed: ${err?.message || String(err)}`);
    } finally {
      setLoadingAudit(false);
    }
  }
  return (
    <div className="space-y-6">
      <section className="rounded-[2rem] border border-white/10 bg-gradient-to-br from-white/10 to-white/5 p-6 shadow-glow backdrop-blur-xl">
        <div className="max-w-3xl">
          <p className="text-xs font-semibold uppercase tracking-[0.35em] text-signal-100/90">Overview</p>
          <h3 className="mt-3 text-4xl font-bold tracking-tight text-white sm:text-5xl">
            A living picture of cloud risk, attack pressure, and remediation velocity.
          </h3>
          <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300 sm:text-base">
            CloudSpecter keeps the story tight: risk summary up front, findings in context, assets under watch, attack flow in motion, and PDFs ready for the room.
          </p>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {kpis.map((kpi) => (
          <MetricCard key={kpi.label} {...kpi} />
        ))}
      </section>

      <section className="grid gap-6 xl:grid-cols-2">
        <ChartCard title="Severity distribution" subtitle="Critical items stay visible with a pulse-first breakdown.">
          <SeverityDoughnut findings={findings} />
        </ChartCard>
        <ChartCard title="Attack timeline" subtitle="Recent activity from probe to response without leaving the page.">
          <AttackTimeline events={attackEvents} />
        </ChartCard>
      </section>

      <section className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-[2rem] border border-white/10 bg-white/5 p-5 shadow-glow backdrop-blur-xl lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-white">Risk summary</h3>
              <p className="text-sm text-slate-400">Inventory and response snapshot</p>
            </div>
            <span className="rounded-full border border-ember-400/30 bg-ember-500/10 px-3 py-1 text-xs font-semibold text-ember-400">
              Elevated
            </span>
          </div>
          <form onSubmit={handleRunAudit} className="mb-4 flex gap-3">
            <input
              className="flex-1 rounded-md border bg-black/10 px-3 py-2 text-sm text-white"
              placeholder="Endpoint URL (e.g. http://localstack:4566)"
              value={endpoint}
              onChange={(ev) => setEndpoint(ev.target.value)}
            />
            <select
              value={region}
              onChange={(ev) => setRegion(ev.target.value)}
              className="rounded-md border bg-black/10 px-3 py-2 text-sm text-white"
            >
              <option value="us-east-1">us-east-1</option>
              <option value="us-west-2">us-west-2</option>
              <option value="eu-west-1">eu-west-1</option>
              <option value="ap-south-1">ap-south-1</option>
            </select>
            <button
              type="submit"
              disabled={loadingAudit}
              className="rounded-md bg-ember-500 px-4 py-2 text-sm font-semibold text-black disabled:opacity-50"
            >
              {loadingAudit ? 'Running…' : 'Run Audit'}
            </button>
          </form>
          {lastAuditMsg && <div className="mb-3 text-sm text-slate-300">{lastAuditMsg}</div>}
          <div className="grid gap-3 sm:grid-cols-2">
            {assets.map((asset) => (
              <div key={asset.name} className="rounded-2xl border border-white/10 bg-black/20 p-4">
                <div className="flex items-center justify-between gap-3">
                  <h4 className="font-semibold text-white">{asset.name}</h4>
                  <span className="rounded-full bg-white/10 px-2.5 py-1 text-[11px] uppercase tracking-[0.24em] text-slate-300">
                    {asset.type}
                  </span>
                </div>
                <p className="mt-2 text-sm text-slate-400">{asset.posture}</p>
                <div className="mt-4 text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Risk: {asset.risk}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-[2rem] border border-white/10 bg-white/5 p-5 shadow-glow backdrop-blur-xl">
          <h3 className="text-lg font-semibold text-white">Signal board</h3>
          <p className="mt-1 text-sm text-slate-400">What the lab is telling you right now.</p>
          <div className="mt-5 space-y-3">
            {[
              'SSRF pressure is visible in the live fetch counter.',
              'IMDS token failures indicate credential theft attempts.',
              'Audit findings keep cloud misconfigurations in the open.',
            ].map((item) => (
              <div key={item} className="rounded-2xl border border-white/10 bg-black/20 p-4 text-sm leading-6 text-slate-300">
                {item}
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
