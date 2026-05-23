import type { Kpi, Finding, Asset, AttackEvent, ReportAsset } from './data';

// Use the Vite proxy during development so browser requests stay same-origin.
const API_BASE = '/api';

async function safeFetch<T>(url: string): Promise<T> {
  const res = await fetch(url, { cache: 'no-store' });
  if (!res.ok) throw new Error(`fetch ${url} failed: ${res.status}`);
  return (await res.json()) as T;
}

export async function fetchKpis(): Promise<Kpi[]> {
  return safeFetch<Kpi[]>(`${API_BASE}/kpis`);
}

export async function fetchFindings(): Promise<Finding[]> {
  // Call the scanner enumerate endpoint and return its findings array.
  const res = await fetch(`${API_BASE}/v1/aws/enumerate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({}),
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`fetch findings failed: ${res.status}`);
  const report = await res.json();
  return (report.findings || []) as Finding[];
}

export async function fetchAssets(): Promise<Asset[]> {
  return safeFetch<Asset[]>(`${API_BASE}/assets`);
}

export async function fetchAttackEvents(): Promise<AttackEvent[]> {
  return safeFetch<AttackEvent[]>(`${API_BASE}/attacks`);
}

export async function runAwsAudit(endpointUrl?: string, region?: string) {
  const payload: Record<string, unknown> = {};
  if (region) payload.region = region;
  if (endpointUrl) payload.endpoint_url = endpointUrl;
  const res = await fetch(`${API_BASE}/v1/aws/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`audit failed: ${res.status}`);
  return (await res.json()) as any;
}

export async function fetchReports(): Promise<ReportAsset[]> {
  // try the API route; caller should fallback to static if this fails
  return safeFetch<ReportAsset[]>(`${API_BASE}/reports`);
}

// Export base for ad-hoc fetches from components
export { API_BASE };
