import React, { useEffect, useState } from 'react';
import { findings as staticFindings, Finding } from '../data';
import { fetchFindings } from '../api';

export function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>(staticFindings);

  useEffect(() => {
    fetchFindings().then((data) => setFindings(data)).catch(() => undefined);
  }, []);

  return (
    <div className="space-y-6">
      <section className="rounded-[2rem] border border-white/10 bg-white/5 p-6 shadow-glow backdrop-blur-xl">
        <p className="text-xs font-semibold uppercase tracking-[0.35em] text-signal-100/90">Findings</p>
        <h3 className="mt-3 text-3xl font-bold tracking-tight text-white">Vulnerabilities and posture issues</h3>
        <p className="mt-4 max-w-3xl text-sm leading-7 text-slate-300">
          A single queue for the issues that matter most. Severity stays visible, MITRE mapping is preserved, and each item carries an asset and remediation status.
        </p>
      </section>

      <section className="overflow-hidden rounded-[2rem] border border-white/10 bg-white/5 shadow-glow backdrop-blur-xl">
        <div className="border-b border-white/10 px-6 py-4 text-sm uppercase tracking-[0.26em] text-slate-400">Finding ledger</div>
        <div className="divide-y divide-white/10">
          {findings.map((finding) => (
            <article key={`${finding.title}-${finding.asset}`} className="grid gap-3 px-6 py-5 lg:grid-cols-[1.2fr_0.6fr_0.9fr_0.8fr] lg:items-center">
              <div>
                <h4 className="text-base font-semibold text-white">{finding.title}</h4>
                <p className="mt-1 text-sm text-slate-400">{finding.impact}</p>
              </div>
              <div className="flex flex-wrap gap-2 text-xs font-semibold uppercase tracking-[0.24em]">
                <span className={`rounded-full px-3 py-1 ${finding.severity === 'Critical' ? 'bg-red-500/15 text-red-300' : finding.severity === 'High' ? 'bg-amber-500/15 text-amber-300' : finding.severity === 'Medium' ? 'bg-signal-500/15 text-signal-100' : 'bg-slate-500/15 text-slate-300'}`}>
                  {finding.severity}
                </span>
                <span className="rounded-full bg-white/10 px-3 py-1 text-slate-300">{finding.status}</span>
              </div>
              <div className="text-sm text-slate-300">
                <div className="font-semibold text-white">{finding.asset}</div>
                <div className="mt-1 text-xs uppercase tracking-[0.24em] text-slate-500">MITRE {finding.mitre}</div>
              </div>
              <div className="text-sm text-slate-400">{finding.status === 'Open' ? 'Prioritize now' : finding.status === 'Investigating' ? 'Under review' : 'Tracked in backlog'}</div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}
