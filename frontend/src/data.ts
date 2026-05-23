export type PageKey = 'overview' | 'findings' | 'assets' | 'exploitation' | 'reports';

export type Kpi = {
  label: string;
  value: string;
  delta: string;
  accent: 'signal' | 'ember' | 'violet' | 'slate';
};

export type Finding = {
  title: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  asset: string;
  mitre: string;
  status: 'Open' | 'Mitigated' | 'Investigating';
  impact: string;
  category?: string;
  evidence?: Record<string, unknown>;
  remediationPriority?: string;
};

export type Asset = {
  name: string;
  type: string;
  risk: string;
  posture: string;
};

export type AttackEvent = {
  time: string;
  source: string;
  target: string;
  action: string;
  outcome: string;
};

export type ReportAsset = {
  title: string;
  description: string;
  href?: string;
  reportId?: string;
  badge: string;
};

export const navigation: { key: PageKey; label: string; subtitle: string }[] = [
  { key: 'overview', label: 'Overview', subtitle: 'Risk summary' },
  { key: 'findings', label: 'Findings', subtitle: 'Vulnerabilities' },
  { key: 'assets', label: 'Assets', subtitle: 'Cloud inventory' },
  { key: 'exploitation', label: 'Exploitation', subtitle: 'Live attack' },
  { key: 'reports', label: 'Reports', subtitle: 'Download PDFs' },
];

export const kpis: Kpi[] = [
  { label: 'Risk score', value: '82', delta: '+12 this week', accent: 'ember' },
  { label: 'Open findings', value: '18', delta: '5 critical', accent: 'signal' },
  { label: 'Assets tracked', value: '42', delta: 'Across 3 accounts', accent: 'slate' },
  { label: 'Blocked attacks', value: '96%', delta: 'Token enforced', accent: 'violet' },
];

export const findings: Finding[] = [
  { title: 'Public S3 bucket', severity: 'Critical', asset: 'finance-data', mitre: 'T1530', status: 'Open', impact: 'Sensitive records may be exposed.' },
  { title: 'IMDSv1 enabled', severity: 'Critical', asset: 'i-0f1a91', mitre: 'T1552.005', status: 'Open', impact: 'SSRF can reach instance metadata without a token.' },
  { title: 'Open security group', severity: 'High', asset: 'sg-028ab', mitre: 'T1190', status: 'Investigating', impact: 'Attack surface exposed on 0.0.0.0/0.' },
  { title: 'Overprivileged IAM role', severity: 'High', asset: 'CloudSpecterAdmin', mitre: 'T1098', status: 'Open', impact: 'Wildcard permissions increase blast radius.' },
  { title: 'Exposed secret', severity: 'High', asset: 'api-prod-token', mitre: 'T1552', status: 'Open', impact: 'Weakly guarded secret can be enumerated.' },
  { title: 'Unencrypted volume', severity: 'Medium', asset: 'vol-09f2', mitre: 'T1005', status: 'Mitigated', impact: 'Data at rest lacks encryption.' },
  { title: 'IMDSv2 enforced', severity: 'Low', asset: 'i-0c8b22', mitre: 'T1552.005', status: 'Mitigated', impact: 'Token protection prevents blind metadata reads.' },
];

export const assets: Asset[] = [
  { name: 'frontend-api', type: 'EC2', risk: 'High', posture: 'Public ingress, token required' },
  { name: 'cloudspecter-bucket', type: 'S3', risk: 'Critical', posture: 'Public ACL detected' },
  { name: 'scanner-role', type: 'IAM Role', risk: 'Medium', posture: 'Scoped read-only policy' },
  { name: 'audit-lambda', type: 'Lambda', risk: 'Low', posture: 'Private runtime' },
  { name: 'vault', type: 'Secrets Manager', risk: 'High', posture: 'Rotation disabled' },
  { name: 'analytics-db', type: 'EBS Volume', risk: 'Medium', posture: 'Encryption pending' },
];

export const attackEvents: AttackEvent[] = [
  { time: '09:14', source: 'SSRF probe', target: 'Image Fetch API', action: 'Attempted metadata fetch', outcome: 'Blocked by token policy' },
  { time: '09:18', source: 'Staging client', target: 'IMDS', action: 'Requested session token', outcome: 'Token issued' },
  { time: '09:22', source: 'Audit job', target: 'S3', action: 'Checked bucket ACL', outcome: 'Public exposure flagged' },
  { time: '09:29', source: 'Scanner', target: 'EC2 metadata', action: 'Read metadata options', outcome: 'IMDSv1 detected' },
  { time: '09:37', source: 'Response team', target: 'IAM', action: 'Reviewed role policy', outcome: 'Least privilege recommended' },
];

export const reportDownloads: ReportAsset[] = [
  { title: 'AWS Audit PDF', description: 'Executive report with findings, risk ratings, and remediation.', reportId: 'aws-audit', badge: 'PDF' },
  { title: 'Metadata Assessment PDF', description: 'SSRF and IMDS validation report for lab comparisons.', reportId: 'assessment', badge: 'PDF' },
  { title: 'Comparison PDF', description: 'Side-by-side vulnerable vs protected environment summary.', reportId: 'comparison', badge: 'PDF' },
  { title: 'Dashboard Pack', description: 'Bundle the latest reports for stakeholder review.', href: '/reports/', badge: 'Folder' },
];

export const severityOrder: ('Critical' | 'High' | 'Medium' | 'Low')[] = ['Critical', 'High', 'Medium', 'Low'];
