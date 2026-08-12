import type { ReactNode } from "react";

export const sevClass: Record<string, string> = {
  critical: "text-sev-critical border-sev-critical/40 bg-sev-critical/10",
  high: "text-sev-high border-sev-high/40 bg-sev-high/10",
  medium: "text-sev-medium border-sev-medium/40 bg-sev-medium/10",
  low: "text-sev-low border-sev-low/40 bg-sev-low/10",
  info: "text-sev-info border-sev-info/40 bg-sev-info/10",
  safe: "text-safe border-safe/40 bg-safe/10",
};

export function SevBadge({ severity, children }: { severity: string; children?: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest ${sevClass[severity] ?? sevClass["info"]}`}
    >
      {children ?? severity}
    </span>
  );
}

export function Panel({
  title,
  hint,
  children,
  className = "",
}: {
  title?: string;
  hint?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel p-5 ${className}`}>
      {title ? (
        <header className="mb-4 flex items-baseline justify-between gap-3 border-b border-border pb-3">
          <h3 className="text-sm font-semibold uppercase tracking-[0.18em] text-foreground">{title}</h3>
          {hint ? <span className="text-[11px] text-muted-foreground">{hint}</span> : null}
        </header>
      ) : null}
      {children}
    </section>
  );
}

export function Stat({ label, value, tone = "" }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className="panel px-4 py-3">
      <div className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground">{label}</div>
      <div className={`mt-1 font-display text-2xl font-semibold ${tone || "text-foreground"}`}>{value}</div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-xs text-muted-foreground">{children}</p>;
}