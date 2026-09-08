export type DnsRecord = { type: string; value: string; ttl?: number | undefined };

export type HostFinding = {
  ip: string;
  ports: number[];
  vulns: string[];
  cpes: string[];
  hostnames: string[];
  tags: string[];
};

export type SubdomainFinding = {
  name: string;
  ips: string[];
  resolved: boolean;
  firstSeen?: string | undefined;
  issuer?: string | undefined;
  via: "ct" | "dns";
};

export type HeaderCheck = {
  name: string;
  present: boolean;
  value?: string | undefined;
  severity: "critical" | "high" | "medium" | "low";
  detail: string;
};

export type RiskItem = {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: "Network" | "TLS" | "Headers" | "Exposure" | "DNS" | "Email";
  evidence: string;
  remediation: string;
};

export type PageFinding = {
  url: string;
  status: number | null;
  title?: string | undefined;
  server?: string | undefined;
  contentType?: string | undefined;
  redirectedTo?: string | undefined;
  source?: "home" | "linked" | "robots" | "sitemap" | "hidden" | undefined;
};

export type WhoisContact = {
  role: string;
  name?: string | undefined;
  org?: string | undefined;
  email?: string | undefined;
  phone?: string | undefined;
  country?: string | undefined;
};

export type WhoisInfo = {
  available: boolean;
  domain: string;
  registrar?: string | undefined;
  registrarIanaId?: string | undefined;
  abuseEmail?: string | undefined;
  abusePhone?: string | undefined;
  createdAt?: string | undefined;
  updatedAt?: string | undefined;
  expiresAt?: string | undefined;
  ageDays?: number | undefined;
  daysToExpiry?: number | undefined;
  expired: boolean;
  statuses: string[];
  nameservers: string[];
  dnssec?: boolean | undefined;
  contacts: WhoisContact[];
  privacyProtected: boolean;
  parked: boolean;
  parkedReason?: string | undefined;
  source?: string | undefined;
};

export type ScanResult = {
  domain: string;
  scannedAt: string;
  durationMs: number;
  score: number;
  grade: string;
  dns: DnsRecord[];
  subdomains: SubdomainFinding[];
  subdomainTotal: number;
  sources: string[];
  hosts: HostFinding[];
  headers: HeaderCheck[];
  pages: PageFinding[];
  risks: RiskItem[];
  tech: string[];
  notes: string[];
  whois?: WhoisInfo | undefined;
};