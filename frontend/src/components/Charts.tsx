import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  Filler,
  Legend,
  LineElement,
  LinearScale,
  PointElement,
  Tooltip,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import type { ReactNode } from 'react';
import type { AttackEvent, Finding } from '../data';
import { severityOrder } from '../data';

ChartJS.register(ArcElement, BarElement, CategoryScale, Filler, Legend, LineElement, LinearScale, PointElement, Tooltip);

type ChartCardProps = {
  title: string;
  subtitle: string;
  children: ReactNode;
};

export function ChartCard({ title, subtitle, children }: ChartCardProps) {
  return (
    <section className="rounded-[2rem] border border-white/10 bg-white/5 p-5 shadow-glow backdrop-blur-xl">
      <div className="mb-5 flex items-end justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          <p className="mt-1 text-sm text-slate-400">{subtitle}</p>
        </div>
      </div>
      <div className="h-[320px]">{children}</div>
    </section>
  );
}

export function SeverityDoughnut({ findings }: { findings: Finding[] }) {
  const counts = severityOrder.map((severity) => findings.filter((finding) => finding.severity === severity).length);

  return (
    <Doughnut
      data={{
        labels: severityOrder,
        datasets: [
          {
            data: counts,
            backgroundColor: ['#ef4444', '#f97316', '#14b8a6', '#94a3b8'],
            borderWidth: 0,
            hoverOffset: 10,
          },
        ],
      }}
      options={{
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#e2e8f0',
              usePointStyle: true,
              pointStyle: 'circle',
              padding: 20,
              boxWidth: 10,
            },
          },
        },
        cutout: '68%',
      }}
    />
  );
}

export function AttackTimeline({ events }: { events: AttackEvent[] }) {
  const scoreEvent = (event: AttackEvent, index: number) => {
    const haystack = `${event.source} ${event.target} ${event.action} ${event.outcome}`.toLowerCase();

    if (haystack.includes('critical')) return 5;
    if (haystack.includes('public') || haystack.includes('exposed')) return 4.2;
    if (haystack.includes('imdsv1') || haystack.includes('metadata')) return 4.6;
    if (haystack.includes('secret')) return 4.8;
    if (haystack.includes('blocked')) return 1.2;
    if (haystack.includes('least privilege') || haystack.includes('remediat')) return 2;
    if (haystack.includes('token')) return 2.6;
    if (haystack.includes('audit') || haystack.includes('scanner')) return 3.2;

    return 1.5 + index * 0.15;
  };

  return (
    <Line
      data={{
        labels: events.map((event) => event.time),
        datasets: [
          {
            label: 'Attack intensity',
            data: events.map((event, index) => scoreEvent(event, index)),
            fill: true,
            borderColor: '#2dd4bf',
            backgroundColor: 'rgba(45, 212, 191, 0.12)',
            tension: 0.28,
            pointRadius: 5,
            pointHoverRadius: 7,
          },
        ],
      }}
      options={{
        maintainAspectRatio: false,
        scales: {
          x: {
            ticks: { color: '#94a3b8' },
            grid: { color: 'rgba(148, 163, 184, 0.12)' },
          },
          y: {
            ticks: { color: '#94a3b8' },
            grid: { color: 'rgba(148, 163, 184, 0.12)' },
          },
        },
        plugins: {
          legend: {
            display: false,
          },
        },
      }}
    />
  );
}

export function AssetBarChart({ findings }: { findings: Finding[] }) {
  type ScoreBreakdown = {
    severity: number;
    findingCount: number;
    criticality: number;
    confidence: number;
    remediationPriority: number;
  };

  type AssetScoreEntry = {
    asset: string;
    score: number;
    breakdown: ScoreBreakdown;
  };

  const severityScore = (severity: Finding['severity']) =>
    ({
      Critical: 36,
      High: 28,
      Medium: 18,
      Low: 8,
    })[severity];

  const criticalityScore = (finding: Finding) => {
    const context = `${finding.category ?? ''} ${finding.asset} ${finding.title}`.toLowerCase();
    if (context.includes('public_s3') || context.includes('bucket') || context.includes('s3')) return 22;
    if (context.includes('secret')) return 20;
    if (context.includes('security group') || context.includes('sg-')) return 18;
    if (context.includes('iam role') || context.includes('iam')) return 16;
    if (context.includes('volume') || context.includes('ebs')) return 14;
    if (context.includes('imdsv1') || context.includes('metadata')) return 17;
    return 10;
  };

  const evidenceConfidenceScore = (finding: Finding) => {
    const evidence = finding.evidence && typeof finding.evidence === 'object' ? finding.evidence : {};
    const evidenceKeys = Object.keys(evidence);
    const category = String(finding.category ?? '').toLowerCase();

    if (category === 'public_s3') return 18;
    if (category === 'open_security_group') return 17;
    if (category === 'exposed_secret') return 16;
    if (category === 'imdsv1' || category === 'imdsv2_enforced') return 16;
    if (category === 'overprivileged_iam_role') return 15;
    if (category === 'unencrypted_volume') return 14;

    return Math.min(12, 6 + evidenceKeys.length * 2);
  };

  const remediationPriorityScore = (finding: Finding) => {
    const category = String(finding.category ?? '').toLowerCase();
    if (category === 'public_s3' || category === 'exposed_secret' || category === 'imdsv1') return 18;
    if (category === 'open_security_group' || category === 'overprivileged_iam_role') return 14;
    if (category === 'unencrypted_volume') return 12;
    if (category === 'imdsv2_enforced') return 4;
    return 8;
  };

  const findingsByAsset = findings.reduce<Record<string, Finding[]>>((accumulator, finding) => {
    const assetKey = finding.asset;
    accumulator[assetKey] = accumulator[assetKey] ?? [];
    accumulator[assetKey].push(finding);
    return accumulator;
  }, {});

  const entries = Object.entries(findingsByAsset)
    .map(([asset, assetFindings]): AssetScoreEntry => {
      const count = assetFindings.length;
      const severityTotal = assetFindings.reduce((total, finding) => total + severityScore(finding.severity), 0);
      const criticalityTotal = assetFindings.reduce((total, finding) => total + criticalityScore(finding), 0);
      const confidenceTotal = assetFindings.reduce((total, finding) => total + evidenceConfidenceScore(finding), 0);
      const remediationTotal = assetFindings.reduce((total, finding) => total + remediationPriorityScore(finding), 0);
      const findingCountScore = count * 7;
      const score = severityTotal + findingCountScore + criticalityTotal + confidenceTotal + remediationTotal;

      return {
        asset,
        score,
        breakdown: {
          severity: severityTotal,
          findingCount: findingCountScore,
          criticality: criticalityTotal,
          confidence: confidenceTotal,
          remediationPriority: remediationTotal,
        },
      };
    })
    .sort((left, right) => right.score - left.score);

  return (
    <Bar
      data={{
        labels: entries.map((entry) => entry.asset),
        datasets: [
          {
            label: 'Exposure score',
            data: entries.map((entry) => entry.score),
            backgroundColor: '#f97316',
            borderColor: '#fb923c',
            borderWidth: 1,
            borderRadius: 12,
            barThickness: 34,
            maxBarThickness: 42,
          },
        ],
      }}
      options={{
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: (items) => entries[items[0]?.dataIndex ?? 0]?.asset ?? '',
              label: (context) => {
                const entry = entries[context.dataIndex];
                if (!entry) return '';
                return [
                  `Exposure score: ${entry.score.toFixed(0)}`,
                  `Severity: ${entry.breakdown.severity}`,
                  `Finding count: ${entry.breakdown.findingCount}`,
                  `Asset criticality: ${entry.breakdown.criticality}`,
                  `Exposure confidence: ${entry.breakdown.confidence}`,
                  `Remediation priority: ${entry.breakdown.remediationPriority}`,
                ];
              },
            },
          },
        },
        scales: {
          x: {
            ticks: { color: '#94a3b8', maxRotation: 0, minRotation: 0, autoSkip: false },
            grid: { display: false },
          },
          y: {
            beginAtZero: true,
            ticks: { color: '#94a3b8' },
            grid: { color: 'rgba(148, 163, 184, 0.12)' },
          },
        },
        layout: { padding: { top: 8 } },
      }}
    />
  );
}
