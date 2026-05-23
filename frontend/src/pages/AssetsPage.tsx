import React, { useEffect, useState } from 'react';
import { assets as staticAssets, findings as staticFindings, Asset, Finding } from '../data';
import { AssetBarChart, ChartCard } from '../components/Charts';
import { runAwsAudit } from '../api';

function text(value: unknown, fallback: string): string {
  if (typeof value === 'string' && value.trim()) {
    return value;
  }
  return fallback;
}

function severityOf(finding: any): Finding['severity'] {
  const severity = text(finding?.finding?.severity ?? finding?.severity, 'Medium');
  if (severity === 'Critical' || severity === 'High' || severity === 'Medium' || severity === 'Low') {
    return severity;
  }
  return 'Medium';
}

function titleOf(finding: any): string {
  return text(finding?.finding?.finding ?? finding?.finding?.title ?? finding?.title ?? finding?.category, 'Unknown finding');
}

function assetNameOf(finding: any): string {
  return text(
    finding?.resource_id ?? finding?.evidence?.bucket ?? finding?.evidence?.arn ?? finding?.evidence?.secret_name,
    'unknown-asset',
  );
}

function assetTypeOf(finding: any): string {
  const category = text(finding?.category, 'asset');
  if (category === 'public_s3') return 'S3';
  if (category === 'exposed_secret') return 'Secrets Manager';
  if (category === 'open_security_group') return 'Security Group';
  if (category === 'overprivileged_iam_role') return 'IAM Role';
  if (category === 'unencrypted_volume') return 'EBS Volume';
  if (category === 'imdsv1' || category === 'imdsv2_enforced') return 'EC2';
  return category.replace(/_/g, ' ').replace(/\b\w/g, (match) => match.toUpperCase());
}

function postureOf(finding: any): string {
  const description = text(finding?.finding?.description ?? finding?.description, 'Posture under review');
  return description;
}

function findingsFromReport(report: any): Finding[] {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  return findings.map((finding: any) => ({
    title: titleOf(finding),
    severity: severityOf(finding),
    asset: assetNameOf(finding),
    mitre: text(finding?.finding?.mitre ?? finding?.mitre, 'N/A'),
    status: severityOf(finding) === 'Low' ? 'Mitigated' : severityOf(finding) === 'Medium' ? 'Investigating' : 'Open',
    impact: postureOf(finding),
    category: text(finding?.category, 'unknown'),
    evidence: finding?.evidence ?? {},
  }));
}

function assetsFromFindings(findings: Finding[], report: any): Asset[] {
  const grouped = new Map<string, Asset>();

  (Array.isArray(report?.findings) ? report.findings : []).forEach((finding: any) => {
    const name = assetNameOf(finding);
    const risk = severityOf(finding);
    const existing = grouped.get(name);
    const asset: Asset = {
      name,
      type: assetTypeOf(finding),
      risk,
      posture: postureOf(finding),
    };

    if (!existing || existing.risk !== 'Critical' || risk === 'Critical') {
      grouped.set(name, asset);
    }
  });

  if (grouped.size > 0) {
    return [...grouped.values()];
  }

  return findings.length > 0
    ? findings.map((finding) => ({ name: finding.asset, type: 'Cloud Resource', risk: finding.severity, posture: finding.impact }))
    : staticAssets;
}

export function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>(staticAssets);
  const [findings, setFindings] = useState<Finding[]>(staticFindings);
  const [endpoint, setEndpoint] = useState('http://localstack:4566');
  const [region, setRegion] = useState('us-east-1');
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);
  const [analysisMessage, setAnalysisMessage] = useState<string | null>(null);

  useEffect(() => {
    runLiveAnalysis().catch(() => undefined);
  }, []);

  async function runLiveAnalysis() {
    setLoadingAnalysis(true);
    setAnalysisMessage(null);
    try {
      const report = await runAwsAudit(endpoint || undefined, region || undefined);
      const liveFindings = findingsFromReport(report);
      const liveAssets = assetsFromFindings(liveFindings, report);
      setFindings(liveFindings);
      setAssets(liveAssets);
      setAnalysisMessage(`Live inventory loaded — ${liveAssets.length} assets, ${liveFindings.length} findings`);
    } catch (error: any) {
      setAnalysisMessage(`Live inventory failed: ${error?.message || String(error)}`);
    } finally {
      setLoadingAnalysis(false);
    }
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    await runLiveAnalysis();
  }

  return (
    <div className="space-y-6">
      <section className="rounded-[2rem] border border-white/10 bg-white/5 p-6 shadow-glow backdrop-blur-xl">
        <p className="text-xs font-semibold uppercase tracking-[0.35em] text-signal-100/90">Assets</p>
        <h3 className="mt-3 text-3xl font-bold tracking-tight text-white">Cloud inventory and exposure map</h3>
        <p className="mt-4 max-w-3xl text-sm leading-7 text-slate-300">
          Inventory is the backbone of response. This page groups your cloud resources by type and keeps their current posture visible alongside the findings that touch them.
        </p>
      </section>

      <section className="rounded-[2rem] border border-white/10 bg-white/5 p-5 shadow-glow backdrop-blur-xl">
        <form className="grid gap-3 lg:grid-cols-[1fr_220px_auto]" onSubmit={handleSubmit}>
          <input
            className="rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm text-white outline-none"
            value={endpoint}
            onChange={(event) => setEndpoint(event.target.value)}
            placeholder="Cloud endpoint or local emulator URL"
          />
          <select
            className="rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm text-white outline-none"
            value={region}
            onChange={(event) => setRegion(event.target.value)}
          >
            <option value="us-east-1">us-east-1</option>
            <option value="us-west-2">us-west-2</option>
            <option value="eu-west-1">eu-west-1</option>
          </select>
          <button
            type="submit"
            className="rounded-xl bg-ember-500 px-5 py-3 text-sm font-semibold text-black transition hover:bg-ember-400 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={loadingAnalysis}
          >
            {loadingAnalysis ? 'Loading…' : 'Load Live Inventory'}
          </button>
        </form>
        {analysisMessage && <p className="mt-3 text-sm text-slate-300">{analysisMessage}</p>}
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <ChartCard title="Assets at risk" subtitle="Each bar combines severity, finding count, asset criticality, exposure confidence, and remediation priority.">
          <AssetBarChart findings={findings} />
        </ChartCard>

        <div className="rounded-[2rem] border border-white/10 bg-white/5 p-5 shadow-glow backdrop-blur-xl">
          <h3 className="text-lg font-semibold text-white">Inventory cards</h3>
          <div className="mt-5 space-y-3">
            {assets.map((asset) => (
              <div key={asset.name} className="rounded-2xl border border-white/10 bg-black/20 p-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-semibold text-white">{asset.name}</div>
                    <div className="text-sm text-slate-400">{asset.posture}</div>
                  </div>
                  <span className="rounded-full bg-white/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-slate-300">
                    {asset.type}
                  </span>
                </div>
                <div className="mt-4 text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">Risk level {asset.risk}</div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
