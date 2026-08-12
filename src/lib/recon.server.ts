import type {
  DnsRecord,
  HeaderCheck,
  HostFinding,
  PageFinding,
  RiskItem,
  ScanResult,
  SubdomainFinding,
} from "./recon.types";

const UA = "Mozilla/5.0 (compatible; SurfaceScan/1.0; +security-audit)";

async function withTimeout<T>(p: (signal: AbortSignal) => Promise<T>, ms: number): Promise<T | null> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await p(ac.signal);
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function pool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx]!);
    }
  });
  await Promise.all(workers);
  return out;
}

const DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"] as const;

export async function resolveDns(name: string, type: string): Promise<DnsRecord[]> {
  const res = await withTimeout(
    (signal) =>
      fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, {
        signal,
        headers: { accept: "application/dns-json" },
      }),
    8000,
  );
  if (!res || !res.ok) return [];
  const json = (await res.json().catch(() => null)) as
    | { Answer?: { type: number; data: string; TTL?: number }[] }
    | null;
  if (!json?.Answer) return [];
  return json.Answer.map((a) => ({ type, value: a.data.replace(/^"|"$/g, ""), ttl: a.TTL }));
}

export async function fullDns(domain: string): Promise<DnsRecord[]> {
  const groups = await pool([...DNS_TYPES], 8, (t) => resolveDns(domain, t));
  const seen = new Set<string>();
  const out: DnsRecord[] = [];
  for (const g of groups) {
    for (const r of g) {
      const k = `${r.type}|${r.value}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(r);
    }
  }
  return out;
}

function addName(
  map: Map<string, SubdomainFinding>,
  raw: string,
  domain: string,
  meta: { firstSeen?: string | undefined; issuer?: string | undefined; via?: "ct" | "dns" },
) {
  const n = raw.trim().toLowerCase().replace(/^\*\./, "");
  if (!n || n.includes(" ") || !(n === domain || n.endsWith(`.${domain}`))) return;
  if (map.has(n)) return;
  map.set(n, {
    name: n,
    ips: [],
    resolved: false,
    firstSeen: meta.firstSeen,
    issuer: meta.issuer,
    via: meta.via ?? "ct",
  });
}

async function fromCrtSh(domain: string, map: Map<string, SubdomainFinding>) {
  const res = await withTimeout(
    (signal) =>
      fetch(`https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`, {
        signal,
        headers: { "user-agent": UA, accept: "application/json" },
      }),
    28000,
  );
  if (!res || !res.ok) return;
  const rows = (await res.json().catch(() => null)) as
    | { name_value?: string; common_name?: string; entry_timestamp?: string; issuer_name?: string }[]
    | null;
  if (!Array.isArray(rows)) return;
  for (const row of rows) {
    const issuer = (row.issuer_name ?? "").match(/CN=([^,]+)/)?.[1];
    for (const piece of `${row.name_value ?? ""}\n${row.common_name ?? ""}`.split("\n")) {
      addName(map, piece, domain, { firstSeen: row.entry_timestamp, issuer });
    }
  }
}

async function fromCertSpotter(domain: string, map: Map<string, SubdomainFinding>) {
  const res = await withTimeout(
    (signal) =>
      fetch(
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`,
        { signal, headers: { "user-agent": UA, accept: "application/json" } },
      ),
    20000,
  );
  if (!res || !res.ok) return;
  const rows = (await res.json().catch(() => null)) as
    | { dns_names?: string[]; not_before?: string; issuer?: { name?: string } }[]
    | null;
  if (!Array.isArray(rows)) return;
  for (const row of rows) {
    const issuer = (row.issuer?.name ?? "").match(/CN=([^,]+)/)?.[1];
    for (const n of row.dns_names ?? []) addName(map, n, domain, { firstSeen: row.not_before, issuer });
  }
}

const COMMON_HOSTS = [
  "www", "mail", "smtp", "imap", "pop", "webmail", "api", "app", "admin", "portal", "dev", "staging",
  "test", "beta", "vpn", "remote", "ftp", "cdn", "static", "assets", "img", "blog", "shop", "store",
  "docs", "support", "help", "status", "dashboard", "auth", "login", "sso", "git", "jenkins", "grafana",
  "kibana", "jira", "db", "database", "backup", "old", "internal", "intranet", "ns1", "ns2", "mx",
];

/** Passive subdomain enumeration: CT logs (crt.sh + CertSpotter) plus a DNS sweep of common hostnames. */
export async function enumerateSubdomains(
  domain: string,
): Promise<{ names: SubdomainFinding[]; total: number; sources: string[] }> {
  const map = new Map<string, SubdomainFinding>();
  const sources: string[] = [];

  await Promise.all([
    fromCrtSh(domain, map).then(() => {
      if (map.size) sources.push("crt.sh");
    }),
    fromCertSpotter(domain, map),
  ]);
  if (map.size && !sources.includes("crt.sh")) sources.push("CertSpotter");
  else if (map.size) sources.push("CertSpotter");

  // DNS brute-sweep of common hostnames catches records never issued a certificate.
  const sweep = await pool(COMMON_HOSTS, 16, async (h) => {
    const name = `${h}.${domain}`;
    if (map.has(name)) return null;
    const recs = await resolveDns(name, "A");
    return recs.length ? name : null;
  });
  let swept = 0;
  for (const name of sweep) {
    if (!name) continue;
    swept++;
    addName(map, name, domain, { issuer: undefined, firstSeen: undefined, via: "dns" });
  }
  if (swept) sources.push("DNS sweep");

  const all = [...map.values()].sort((a, b) => a.name.length - b.name.length || a.name.localeCompare(b.name));
  return { names: all, total: all.length, sources };
}

export async function resolveSubdomains(subs: SubdomainFinding[], limit: number): Promise<SubdomainFinding[]> {
  const slice = subs.slice(0, limit);
  await pool(slice, 12, async (s) => {
    const recs = await resolveDns(s.name, "A");
    s.ips = recs.map((r) => r.value).filter((v) => /^\d+\.\d+\.\d+\.\d+$/.test(v));
    s.resolved = s.ips.length > 0;
  });
  return [...slice, ...subs.slice(limit)];
}

/** Open ports / exposed services / known CVEs per IP (Shodan InternetDB, passive). */
export async function scanHosts(ips: string[]): Promise<HostFinding[]> {
  const results = await pool(ips, 8, async (ip) => {
    const res = await withTimeout(
      (signal) => fetch(`https://internetdb.shodan.io/${ip}`, { signal, headers: { accept: "application/json" } }),
      9000,
    );
    if (!res || !res.ok) return null;
    const j = (await res.json().catch(() => null)) as HostFinding | null;
    if (!j || !Array.isArray(j.ports)) return null;
    return {
      ip,
      ports: j.ports ?? [],
      vulns: j.vulns ?? [],
      cpes: j.cpes ?? [],
      hostnames: j.hostnames ?? [],
      tags: j.tags ?? [],
    } satisfies HostFinding;
  });
  return results.filter((r): r is HostFinding => r !== null);
}

const HEADER_SPEC: {
  key: string;
  name: string;
  severity: HeaderCheck["severity"];
  detail: string;
}[] = [
  {
    key: "strict-transport-security",
    name: "Strict-Transport-Security",
    severity: "high",
    detail: "Forces HTTPS and blocks SSL-stripping downgrade attacks.",
  },
  {
    key: "content-security-policy",
    name: "Content-Security-Policy",
    severity: "high",
    detail: "Primary defence against cross-site scripting and injected resources.",
  },
  {
    key: "x-frame-options",
    name: "X-Frame-Options",
    severity: "medium",
    detail: "Blocks clickjacking via framing of your pages.",
  },
  {
    key: "x-content-type-options",
    name: "X-Content-Type-Options",
    severity: "medium",
    detail: "Stops MIME-type sniffing of responses.",
  },
  {
    key: "referrer-policy",
    name: "Referrer-Policy",
    severity: "low",
    detail: "Prevents leaking full URLs to third-party sites.",
  },
  {
    key: "permissions-policy",
    name: "Permissions-Policy",
    severity: "low",
    detail: "Restricts camera, mic, geolocation and other powerful features.",
  },
  {
    key: "cross-origin-opener-policy",
    name: "Cross-Origin-Opener-Policy",
    severity: "low",
    detail: "Isolates your browsing context from cross-origin windows.",
  },
];

export async function inspectOrigin(domain: string): Promise<{
  checks: HeaderCheck[];
  home: PageFinding | null;
  html: string;
  tech: string[];
  httpsOk: boolean;
}> {
  const res = await withTimeout(
    (signal) => fetch(`https://${domain}/`, { signal, headers: { "user-agent": UA }, redirect: "follow" }),
    15000,
  );
  if (!res) {
    return { checks: [], home: null, html: "", tech: [], httpsOk: false };
  }
  const html = await res.text().catch(() => "");
  const h = res.headers;
  const checks: HeaderCheck[] = HEADER_SPEC.map((spec) => {
    const value = h.get(spec.key);
    return {
      name: spec.name,
      present: Boolean(value),
      value: value ?? undefined,
      severity: spec.severity,
      detail: spec.detail,
    };
  });

  const tech = new Set<string>();
  const server = h.get("server");
  if (server) tech.add(server);
  const powered = h.get("x-powered-by");
  if (powered) tech.add(powered);
  for (const [pattern, label] of [
    [/cf-ray/i, "Cloudflare"],
    [/x-vercel-id/i, "Vercel"],
    [/x-amz-cf-id/i, "AWS CloudFront"],
    [/x-github-request-id/i, "GitHub Pages"],
    [/x-shopify/i, "Shopify"],
  ] as [RegExp, string][]) {
    for (const key of h.keys()) if (pattern.test(key)) tech.add(label);
  }
  if (/wp-content|wp-includes/i.test(html)) tech.add("WordPress");
  if (/__NEXT_DATA__/.test(html)) tech.add("Next.js");
  if (/data-reactroot|react/i.test(html) && /_next|react-dom/i.test(html)) tech.add("React");

  const home: PageFinding = {
    url: `https://${domain}/`,
    status: res.status,
    title: html.match(/<title[^>]*>([^<]{1,160})<\/title>/i)?.[1]?.trim(),
    server: server ?? undefined,
    contentType: h.get("content-type") ?? undefined,
    redirectedTo: res.url && res.url !== `https://${domain}/` ? res.url : undefined,
  };

  return { checks, home, html, tech: [...tech], httpsOk: res.status < 500 };
}

export function extractLinks(html: string, domain: string, cap: number): string[] {
  const urls = new Set<string>();
  const re = /href\s*=\s*["']([^"'#]+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null && urls.size < cap * 4) {
    const raw = m[1]!.trim();
    if (!raw || raw.startsWith("mailto:") || raw.startsWith("tel:") || raw.startsWith("javascript:")) continue;
    try {
      const u = new URL(raw, `https://${domain}/`);
      if (!u.hostname.endsWith(domain)) continue;
      if (/\.(png|jpe?g|gif|svg|webp|css|js|ico|woff2?|pdf|zip|mp4)$/i.test(u.pathname)) continue;
      u.hash = "";
      u.search = "";
      if (u.href === `https://${domain}/`) continue;
      urls.add(u.href);
    } catch {
      /* ignore malformed href */
    }
  }
  return [...urls].slice(0, cap);
}

export async function probePages(urls: string[]): Promise<PageFinding[]> {
  return pool(urls, 8, async (url) => {
    const res = await withTimeout(
      (signal) => fetch(url, { signal, headers: { "user-agent": UA }, redirect: "follow" }),
      10000,
    );
    if (!res) return { url, status: null };
    const ct = res.headers.get("content-type") ?? "";
    let title: string | undefined;
    if (ct.includes("text/html")) {
      const body = await res.text().catch(() => "");
      title = body.match(/<title[^>]*>([^<]{1,160})<\/title>/i)?.[1]?.trim();
    }
    return {
      url,
      status: res.status,
      title,
      server: res.headers.get("server") ?? undefined,
      contentType: ct || undefined,
      redirectedTo: res.url !== url ? res.url : undefined,
    } satisfies PageFinding;
  });
}

const RISKY_PORTS: Record<number, { label: string; severity: RiskItem["severity"]; why: string }> = {
  21: { label: "FTP", severity: "high", why: "Plaintext credentials and file transfer." },
  22: { label: "SSH", severity: "medium", why: "Remote shell exposed to the whole internet." },
  23: { label: "Telnet", severity: "critical", why: "Unencrypted remote shell — never expose." },
  25: { label: "SMTP", severity: "medium", why: "Mail relay exposure and abuse risk." },
  53: { label: "DNS", severity: "low", why: "Open resolvers can be used for amplification attacks." },
  110: { label: "POP3", severity: "medium", why: "Legacy plaintext mail retrieval." },
  135: { label: "MSRPC", severity: "high", why: "Windows RPC should never be internet-facing." },
  139: { label: "NetBIOS", severity: "high", why: "Legacy Windows file sharing." },
  445: { label: "SMB", severity: "critical", why: "Primary ransomware entry point." },
  1433: { label: "MSSQL", severity: "critical", why: "Database directly reachable from the internet." },
  3306: { label: "MySQL", severity: "critical", why: "Database directly reachable from the internet." },
  3389: { label: "RDP", severity: "critical", why: "Top target for brute force and ransomware." },
  5432: { label: "PostgreSQL", severity: "critical", why: "Database directly reachable from the internet." },
  5900: { label: "VNC", severity: "critical", why: "Remote desktop, frequently unauthenticated." },
  6379: { label: "Redis", severity: "critical", why: "Often unauthenticated by default." },
  9200: { label: "Elasticsearch", severity: "critical", why: "Common source of mass data leaks." },
  27017: { label: "MongoDB", severity: "critical", why: "Common source of mass data leaks." },
  11211: { label: "Memcached", severity: "high", why: "Amplification DDoS vector." },
  8080: { label: "HTTP alt", severity: "low", why: "Secondary web service, often an unhardened admin app." },
  8443: { label: "HTTPS alt", severity: "low", why: "Secondary TLS service, often a management console." },
};

export function portInfo(port: number) {
  return RISKY_PORTS[port];
}

const SEV_WEIGHT: Record<RiskItem["severity"], number> = {
  critical: 22,
  high: 12,
  medium: 6,
  low: 2,
  info: 0,
};

export function buildRisks(input: {
  domain: string;
  dns: DnsRecord[];
  hosts: HostFinding[];
  headers: HeaderCheck[];
  subdomains: SubdomainFinding[];
  pages: PageFinding[];
}): RiskItem[] {
  const risks: RiskItem[] = [];

  for (const host of input.hosts) {
    for (const port of host.ports) {
      const info = RISKY_PORTS[port];
      if (!info) continue;
      risks.push({
        id: `port-${host.ip}-${port}`,
        title: `Exposed ${info.label} service on port ${port}`,
        severity: info.severity,
        category: "Network",
        evidence: `${host.ip} has TCP/${port} reachable from the public internet${host.hostnames.length ? ` (${host.hostnames.slice(0, 2).join(", ")})` : ""}.`,
        remediation: `${info.why} Restrict TCP/${port} with a firewall or security group, or place it behind a VPN/bastion.`,
      });
    }
    for (const cve of host.vulns) {
      risks.push({
        id: `cve-${host.ip}-${cve}`,
        title: `${cve} affects ${host.ip}`,
        severity: "critical",
        category: "Exposure",
        evidence: `Known vulnerability ${cve} is associated with the software fingerprinted on ${host.ip}.`,
        remediation: `Review ${cve} in the NVD and patch or upgrade the affected service immediately.`,
      });
    }
  }

  for (const check of input.headers) {
    if (check.present) continue;
    risks.push({
      id: `hdr-${check.name}`,
      title: `Missing ${check.name} header`,
      severity: check.severity,
      category: "Headers",
      evidence: `The response from https://${input.domain}/ does not set ${check.name}.`,
      remediation: check.detail,
    });
  }

  const txt = input.dns.filter((r) => r.type === "TXT").map((r) => r.value);
  const spf = txt.find((v) => v.toLowerCase().startsWith("v=spf1"));
  if (!spf) {
    risks.push({
      id: "spf",
      title: "No SPF record published",
      severity: "high",
      category: "Email",
      evidence: `No "v=spf1" TXT record found for ${input.domain}.`,
      remediation: "Publish an SPF record listing authorised senders and end it with -all to stop spoofing.",
    });
  } else if (/\+all|(?:^|\s)\?all/.test(spf)) {
    risks.push({
      id: "spf-weak",
      title: "Permissive SPF policy",
      severity: "medium",
      category: "Email",
      evidence: spf,
      remediation: "Replace +all / ?all with -all or ~all so unauthorised senders are rejected.",
    });
  }
  if (!input.dns.some((r) => r.type === "CAA")) {
    risks.push({
      id: "caa",
      title: "No CAA record",
      severity: "low",
      category: "TLS",
      evidence: `${input.domain} does not restrict which CAs may issue certificates.`,
      remediation: "Add a CAA record naming your certificate authority to prevent unauthorised issuance.",
    });
  }

  const dev = input.subdomains.filter((s) =>
    /^(dev|test|stage|staging|uat|qa|beta|admin|internal|vpn|jenkins|grafana|kibana|jira|git|db|backup|old)[.-]/.test(
      s.name.replace(`.${input.domain}`, "") + ".",
    ),
  );
  for (const s of dev.slice(0, 12)) {
    risks.push({
      id: `sub-${s.name}`,
      title: `Sensitive-looking host discovered: ${s.name}`,
      severity: s.resolved ? "medium" : "low",
      category: "Exposure",
      evidence: s.resolved
        ? `${s.name} resolves to ${s.ips.join(", ")} and appears in public certificate transparency logs.`
        : `${s.name} appears in certificate transparency logs but does not currently resolve.`,
      remediation: s.resolved
        ? "Confirm this non-production or admin host requires authentication and IP allow-listing."
        : "Dangling CT entries can indicate stale infrastructure or subdomain-takeover risk — verify ownership.",
    });
  }

  const broken = input.pages.filter((p) => p.status !== null && p.status >= 500);
  if (broken.length) {
    risks.push({
      id: "pages-5xx",
      title: `${broken.length} page(s) returning server errors`,
      severity: "medium",
      category: "Exposure",
      evidence: broken
        .slice(0, 5)
        .map((p) => `${p.status} ${p.url}`)
        .join("\n"),
      remediation: "Server errors can leak stack traces and internal paths. Fix and return generic error pages.",
    });
  }

  const order = ["critical", "high", "medium", "low", "info"];
  return risks.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
}

/**
 * Weighted score with diminishing returns: repeated findings of the same kind
 * add less, and each category is capped so one noisy area can't zero the score.
 */
export function scoreRisks(risks: RiskItem[]): { score: number; grade: string } {
  const byCategory = new Map<string, RiskItem[]>();
  for (const r of risks) {
    const list = byCategory.get(r.category) ?? [];
    list.push(r);
    byCategory.set(r.category, list);
  }
  const order = ["critical", "high", "medium", "low", "info"];
  let penalty = 0;
  for (const list of byCategory.values()) {
    const sorted = [...list].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    let cat = 0;
    sorted.forEach((r, i) => {
      cat += SEV_WEIGHT[r.severity] / Math.sqrt(i + 1);
    });
    penalty += Math.min(cat, 34);
  }
  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { score, grade };
}

export function normalizeDomain(input: string): string {
  let d = input.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "").replace(/^www\./, "");
  d = d.split("/")[0]!.split(":")[0]!;
  return d;
}

export async function runScan(rawDomain: string): Promise<ScanResult> {
  const started = Date.now();
  const domain = normalizeDomain(rawDomain);
  const notes: string[] = [];

  const [dns, ct, origin] = await Promise.all([
    fullDns(domain),
    enumerateSubdomains(domain),
    inspectOrigin(domain),
  ]);

  if (!ct.total) notes.push("No subdomains found — public certificate log providers may be rate limiting.");
  if (!origin.home) notes.push(`Could not complete an HTTPS request to ${domain} — headers were not assessed.`);

  const subdomains = await resolveSubdomains(ct.names, 60);

  const ipSet = new Set<string>();
  for (const r of dns) if (r.type === "A") ipSet.add(r.value);
  for (const s of subdomains) for (const ip of s.ips) ipSet.add(ip);
  const ips = [...ipSet].slice(0, 30);

  const linkUrls = extractLinks(origin.html, domain, 24);
  const [hosts, pages] = await Promise.all([scanHosts(ips), probePages(linkUrls)]);

  const allPages = origin.home ? [origin.home, ...pages] : pages;
  const risks = buildRisks({ domain, dns, hosts, headers: origin.checks, subdomains, pages: allPages });
  const { score, grade } = scoreRisks(risks);

  return {
    domain,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    score,
    grade,
    dns,
    subdomains: subdomains.slice(0, 250),
    subdomainTotal: ct.total,
    sources: ct.sources,
    hosts,
    headers: origin.checks,
    pages: allPages,
    risks,
    tech: origin.tech,
    notes,
  };
}