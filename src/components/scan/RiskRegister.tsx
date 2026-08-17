import { useMemo, useState } from "react";
import { ChevronDown, Sparkles, ShieldCheck } from "lucide-react";
import type { RiskItem } from "@/lib/recon.types";
import { Empty, Panel, SevBadge } from "./primitives";

const ORDER = ["critical", "high", "medium", "low", "info"] as const;
type Sev = (typeof ORDER)[number];

const BAR: Record<Sev, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const CHIP: Record<Sev, string> = {
  critical: "text-sev-critical border-sev-critical/50 bg-sev-critical/10",
  high: "text-sev-high border-sev-high/50 bg-sev-high/10",
  medium: "text-sev-medium border-sev-medium/50 bg-sev-medium/10",
  low: "text-sev-low border-sev-low/50 bg-sev-low/10",
  info: "text-sev-info border-sev-info/50 bg-sev-info/10",
};

type Group = {
  key: string;
  title: string;
  severity: string;
  category: string;
  remediation: string;
  items: RiskItem[];
};

function groupKey(r: RiskItem) {
  const head = r.title.includes(":") ? r.title.split(":")[0]!.trim() : r.title;
  return `${r.severity}|${r.category}|${head}`;
}

function groupRisks(risks: RiskItem[]): Group[] {
  const map = new Map<string, Group>();
  for (const r of risks) {
    const key = groupKey(r);
    const existing = map.get(key);
    if (existing) existing.items.push(r);
    else
      map.set(key, {
        key,
        title: r.title.includes(":") ? r.title.split(":")[0]!.trim() : r.title,
        severity: r.severity,
        category: r.category,
        remediation: r.remediation,
        items: [r],
      });
  }
  return [...map.values()].sort(
    (a, b) =>
      ORDER.indexOf(a.severity as Sev) - ORDER.indexOf(b.severity as Sev) || b.items.length - a.items.length,
  );
}

function GroupCard({ group }: { group: Group }) {
  const single = group.items.length === 1;
  const [open, setOpen] = useState(single);
  const first = group.items[0]!;

  return (
    <li className="overflow-hidden rounded border border-border bg-background/40">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 p-4 text-left transition-colors hover:bg-secondary/40"
      >
        <span className="mt-0.5">
          <SevBadge severity={group.severity} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-display text-sm font-semibold text-foreground">
              {single ? first.title : group.title}
            </span>
            {!single ? (
              <span className="rounded border border-border bg-secondary px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                ×{group.items.length}
              </span>
            ) : null}
          </span>
          <span className="mt-1 block text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
            {group.category}
          </span>
          {!open && !single ? (
            <span className="mt-2 block truncate font-mono text-[11px] text-muted-foreground">
              {group.items
                .map((i) => (i.title.includes(":") ? i.title.split(":").slice(1).join(":").trim() : i.title))
                .join(", ")}
            </span>
          ) : null}
        </span>
        <ChevronDown className={`mt-1 size-4 shrink-0 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open ? (
        <div className="border-t border-border/60 px-4 pb-4 pt-3">
          <ul className="space-y-2">
            {group.items.map((r) => (
              <li key={r.id} className="rounded border border-border/50 bg-card/40 p-3">
                {!single ? (
                  <p className="mb-1 font-mono text-xs font-semibold text-primary">
                    {r.title.includes(":") ? r.title.split(":").slice(1).join(":").trim() : r.title}
                  </p>
                ) : null}
                <pre className="whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed text-muted-foreground">
                  {r.evidence}
                </pre>
              </li>
            ))}
          </ul>
          <p className="mt-3 flex gap-2 text-xs text-primary/90">
            <Sparkles className="mt-0.5 size-3.5 shrink-0" />
            {group.remediation}
          </p>
        </div>
      ) : null}
    </li>
  );
}

export function RiskRegister({ risks }: { risks: RiskItem[] }) {
  const [filter, setFilter] = useState<Sev | "all">("all");

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of risks) c[r.severity] = (c[r.severity] ?? 0) + 1;
    return c;
  }, [risks]);

  const groups = useMemo(
    () => groupRisks(filter === "all" ? risks : risks.filter((r) => r.severity === filter)),
    [risks, filter],
  );

  const total = risks.length;

  return (
    <Panel
      title="Risk register"
      hint={`${total} finding${total === 1 ? "" : "s"} in ${groupRisks(risks).length} issue type(s)`}
    >
      {total === 0 ? (
        <Empty>
          <ShieldCheck className="mx-auto mb-2 size-5 text-safe" />
          No issues detected from passive analysis.
        </Empty>
      ) : (
        <>
          <div className="mb-4 flex h-1.5 w-full overflow-hidden rounded-full bg-secondary">
            {ORDER.map((s) =>
              counts[s] ? (
                <div
                  key={s}
                  title={`${counts[s]} ${s}`}
                  style={{ width: `${((counts[s] ?? 0) / total) * 100}%` }}
                  className={`h-full ${BAR[s]}`}
                />
              ) : null,
            )}
          </div>

          <div className="mb-4 flex flex-wrap gap-2">
            <button
              onClick={() => setFilter("all")}
              className={`rounded border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                filter === "all"
                  ? "border-primary/50 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:text-foreground"
              }`}
            >
              All {total}
            </button>
            {ORDER.filter((s) => counts[s]).map((s) => (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={`rounded border px-2.5 py-1 text-[11px] font-medium uppercase tracking-widest transition-colors ${
                  filter === s ? CHIP[s] : "border-border text-muted-foreground hover:text-foreground"
                }`}
              >
                {s} {counts[s]}
              </button>
            ))}
          </div>

          <ul className="space-y-2">
            {groups.map((g) => (
              <GroupCard key={g.key} group={g} />
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
}
