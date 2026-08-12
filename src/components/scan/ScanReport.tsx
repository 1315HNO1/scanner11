import { useState } from "react";
import {
  AlertTriangle,
  Globe,
  Network,
  ScrollText,
  ServerCog,
  ShieldCheck,
  Sparkles,
  FileText,
} from "lucide-react";
import type { ScanResult } from "@/lib/recon.types";
import { Empty, Panel, SevBadge, Stat } from "./primitives";

const TABS = [
  { id: "risks", label: "Risk register", icon: AlertTriangle },
  { id: "hosts", label: "Ports & IPs", icon: Network },
  { id: "subs", label: "Subdomains", icon: Globe },
  { id: "pages", label: "Pages", icon: FileText },
  { id: "dns", label: "DNS", icon: ServerCog },
  { id: "headers", label: "Headers", icon: ShieldCheck },
] as const;

type TabId = (typeof TABS)[number]["id"];

const PORT_LABELS: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  445: "SMB",
  587: "SMTP/TLS",
  993: "IMAPS",
  1433: "MSSQL",
  3306: "MySQL",
  3389: "RDP",
  5432: "Postgres",
  5900: "VNC",
  6379: "Redis",
  8080: "HTTP-alt",
  8443: "HTTPS-alt",
  9200: "Elastic",
  27017: "MongoDB",
};

const DANGEROUS = new Set([21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017]);

function gradeTone(grade: string) {
  if (grade === "A") return "text-safe";
  if (grade === "B") return "text-sev-low";
  if (grade === "C") return "text-sev-medium";
  if (grade === "D") return "text-sev-high";
  return "text-sev-critical";
}

export function ScanReport({ result }: { result: ScanResult }) {
  const [tab, setTab] = useState<TabId>("risks");

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<string, number>;
  for (const r of result.risks) counts[r.severity] = (counts[r.severity] ?? 0) + 1;
  const openPorts = new Set<number>();
  for (const h of result.hosts) for (const p of h.ports) openPorts.add(p);
  const cves = result.hosts.flatMap((h) => h.vulns);

  return (
    <div className="space-y-6">
      <div className="panel glow flex flex-col gap-6 p-6 md:flex-row md:items-center">
        <div className="flex items-center gap-5">
          <div className="relative grid size-24 shrink-0 place-items-center">
            <svg viewBox="0 0 100 100" className="absolute inset-0 -rotate-90">
              <circle cx="50" cy="50" r="44" fill="none" stroke="currentColor" strokeWidth="6" className="text-border" />
              <circle
                cx="50"
                cy="50"
                r="44"
                fill="none"
                stroke="currentColor"
                strokeWidth="6"
                strokeLinecap="round"
                strokeDasharray={`${(result.score / 100) * 276.4} 276.4`}
                className={gradeTone(result.grade)}
              />
            </svg>
            <div className="text-center">
              <div className={`font-display text-3xl font-bold ${gradeTone(result.grade)}`}>{result.grade}</div>
              <div className="text-[10px] text-muted-foreground">{result.score}/100</div>
            </div>
          </div>
          <div>
            <h2 className="font-display text-2xl font-semibold text-foreground">{result.domain}</h2>
            <p className="mt-1 text-xs text-muted-foreground">
              Scanned {new Date(result.scannedAt).toLocaleString()} · {(result.durationMs / 1000).toFixed(1)}s
            </p>
            {result.tech.length ? (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {result.tech.slice(0, 6).map((t) => (
                  <span key={t} className="rounded border border-border bg-secondary px-2 py-0.5 text-[10px] text-muted-foreground">
                    {t}
                  </span>
                ))}
              </div>
            ) : null}
          </div>
        </div>
        <div className="grid flex-1 grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
          <Stat label="Critical" value={counts["critical"] ?? 0} tone="text-sev-critical" />
          <Stat label="High" value={counts["high"] ?? 0} tone="text-sev-high" />
          <Stat label="Subdomains" value={result.subdomainTotal} />
          <Stat label="Live IPs" value={result.hosts.length} />
          <Stat label="Open ports" value={openPorts.size} tone={openPorts.size > 6 ? "text-sev-medium" : ""} />
        </div>
      </div>

      {result.notes.length ? (
        <div className="panel border-sev-medium/40 p-4 text-xs text-sev-medium">
          {result.notes.map((n) => (
            <p key={n}>▲ {n}</p>
          ))}
        </div>
      ) : null}

      <nav className="flex flex-wrap gap-2">
        {TABS.map((t) => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`inline-flex items-center gap-2 rounded border px-3 py-2 text-xs font-medium transition-colors ${
                active
                  ? "border-primary/50 bg-primary/10 text-primary"
                  : "border-border bg-card/50 text-muted-foreground hover:text-foreground"
              }`}
            >
              <Icon className="size-3.5" />
              {t.label}
            </button>
          );
        })}
      </nav>

      {tab === "risks" ? (
        <Panel title="Risk register" hint={`${result.risks.length} findings, ranked by severity`}>
          {result.risks.length === 0 ? (
            <Empty>No issues detected from passive analysis.</Empty>
          ) : (
            <ul className="space-y-3">
              {result.risks.map((r) => (
                <li key={r.id} className="rounded border border-border bg-background/40 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <SevBadge severity={r.severity} />
                    <span className="text-[10px] uppercase tracking-widest text-muted-foreground">{r.category}</span>
                    <h4 className="w-full font-display text-sm font-semibold text-foreground sm:w-auto">{r.title}</h4>
                  </div>
                  <pre className="mt-2 whitespace-pre-wrap break-words text-xs text-muted-foreground">{r.evidence}</pre>
                  <p className="mt-2 flex gap-2 text-xs text-primary/90">
                    <Sparkles className="mt-0.5 size-3.5 shrink-0" />
                    {r.remediation}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      ) : null}

      {tab === "hosts" ? (
        <Panel title="Network surface" hint="IP addresses, open ports and known CVEs">
          {result.hosts.length === 0 ? (
            <Empty>No reachable IP addresses were fingerprinted.</Empty>
          ) : (
            <div className="space-y-3">
              {cves.length ? (
                <p className="rounded border border-sev-critical/40 bg-sev-critical/10 p-3 text-xs text-sev-critical">
                  {cves.length} known CVE(s) associated with this infrastructure.
                </p>
              ) : null}
              {result.hosts.map((h) => (
                <div key={h.ip} className="rounded border border-border bg-background/40 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono text-sm font-semibold text-primary">{h.ip}</span>
                    <span className="text-[11px] text-muted-foreground">{h.ports.length} open port(s)</span>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {h.ports.map((p) => (
                      <span
                        key={p}
                        className={`rounded border px-2 py-1 text-[11px] ${
                          DANGEROUS.has(p)
                            ? "border-sev-critical/50 bg-sev-critical/10 text-sev-critical"
                            : "border-border bg-secondary text-foreground"
                        }`}
                      >
                        {p}
                        {PORT_LABELS[p] ? <span className="ml-1 opacity-60">{PORT_LABELS[p]}</span> : null}
                      </span>
                    ))}
                  </div>
                  {h.vulns.length ? (
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {h.vulns.map((v) => (
                        <a
                          key={v}
                          href={`https://nvd.nist.gov/vuln/detail/${v}`}
                          target="_blank"
                          rel="noreferrer"
                          className="rounded border border-sev-critical/50 bg-sev-critical/10 px-2 py-0.5 text-[11px] text-sev-critical underline-offset-2 hover:underline"
                        >
                          {v}
                        </a>
                      ))}
                    </div>
                  ) : null}
                  {h.cpes.length ? (
                    <p className="mt-3 break-words text-[11px] text-muted-foreground">{h.cpes.join("  ·  ")}</p>
                  ) : null}
                  {h.hostnames.length ? (
                    <p className="mt-2 break-words text-[11px] text-muted-foreground">
                      PTR: {h.hostnames.slice(0, 6).join(", ")}
                    </p>
                  ) : null}
                </div>
              ))}
            </div>
          )}
        </Panel>
      ) : null}

      {tab === "subs" ? (
        <Panel
          title="Subdomains"
          hint={`${result.subdomainTotal} discovered via ${result.sources.join(" + ") || "public sources"} · first 60 resolved`}
        >
          {result.subdomains.length === 0 ? (
            <Empty>No subdomains found in public certificate logs.</Empty>
          ) : (
            <div className="max-h-[32rem] overflow-auto">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-card text-[10px] uppercase tracking-widest text-muted-foreground">
                  <tr>
                    <th className="py-2 pr-3 font-medium">Host</th>
                    <th className="py-2 pr-3 font-medium">Resolves to</th>
                    <th className="py-2 pr-3 font-medium">Source</th>
                    <th className="py-2 font-medium">Issuer</th>
                  </tr>
                </thead>
                <tbody>
                  {result.subdomains.map((s) => (
                    <tr key={s.name} className="border-t border-border/60">
                      <td className="py-2 pr-3">
                        <span className={s.resolved ? "text-foreground" : "text-muted-foreground"}>{s.name}</span>
                      </td>
                      <td className="py-2 pr-3 font-mono text-primary/80">{s.ips.join(", ") || "—"}</td>
                      <td className="py-2 pr-3 text-muted-foreground">{s.via === "dns" ? "DNS" : "CT log"}</td>
                      <td className="py-2 text-muted-foreground">{s.issuer ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      ) : null}

      {tab === "pages" ? (
        <Panel title="Crawled pages" hint="Same-origin links discovered from the homepage">
          {result.pages.length === 0 ? (
            <Empty>No pages could be reached.</Empty>
          ) : (
            <ul className="space-y-1.5">
              {result.pages.map((p) => (
                <li key={p.url} className="flex flex-wrap items-center gap-3 rounded border border-border/60 px-3 py-2 text-xs">
                  <span
                    className={`w-10 shrink-0 font-mono font-semibold ${
                      p.status === null
                        ? "text-sev-info"
                        : p.status >= 500
                          ? "text-sev-critical"
                          : p.status >= 400
                            ? "text-sev-medium"
                            : "text-safe"
                    }`}
                  >
                    {p.status ?? "ERR"}
                  </span>
                  <a href={p.url} target="_blank" rel="noreferrer" className="truncate text-foreground hover:text-primary">
                    {p.url}
                  </a>
                  {p.title ? <span className="truncate text-muted-foreground">— {p.title}</span> : null}
                </li>
              ))}
            </ul>
          )}
        </Panel>
      ) : null}

      {tab === "dns" ? (
        <Panel title="DNS records" hint="A / AAAA / MX / NS / TXT / CNAME / SOA / CAA">
          {result.dns.length === 0 ? (
            <Empty>No DNS records resolved.</Empty>
          ) : (
            <ul className="space-y-1">
              {result.dns.map((r) => (
                <li key={`${r.type}-${r.value}`} className="flex gap-3 border-b border-border/40 py-1.5 text-xs">
                  <span className="w-14 shrink-0 font-semibold text-primary">{r.type}</span>
                  <span className="break-all text-muted-foreground">{r.value}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      ) : null}

      {tab === "headers" ? (
        <Panel title="Security headers" hint={`https://${result.domain}/`}>
          {result.headers.length === 0 ? (
            <Empty>Origin did not respond to an HTTPS request.</Empty>
          ) : (
            <ul className="space-y-2">
              {result.headers.map((h) => (
                <li key={h.name} className="rounded border border-border/60 p-3 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <SevBadge severity={h.present ? "safe" : h.severity}>{h.present ? "set" : "missing"}</SevBadge>
                    <span className="font-semibold text-foreground">{h.name}</span>
                  </div>
                  <p className="mt-1.5 break-all text-muted-foreground">{h.value ?? h.detail}</p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      ) : null}

      <p className="flex items-start gap-2 text-[11px] leading-relaxed text-muted-foreground">
        <ScrollText className="mt-0.5 size-3.5 shrink-0" />
        All data is gathered passively from public sources (certificate transparency logs, public DNS, the Shodan
        InternetDB fingerprint index and normal HTTPS requests). No intrusive probing is performed. Only scan domains
        you own or are authorised to test.
      </p>
    </div>
  );
}