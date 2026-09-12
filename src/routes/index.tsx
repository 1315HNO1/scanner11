import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { Radar, Search, Loader2 } from "lucide-react";
import { scanDomain } from "@/lib/recon.functions";
import { ScanReport } from "@/components/scan/ScanReport";

const TITLE = "SurfaceScan — Attack Surface & Subdomain Scanner";
const DESC =
  "Map every subdomain, page, IP address and open port of any domain, then get a ranked risk register with remediation steps.";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: TITLE },
      { name: "description", content: DESC },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESC },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      { property: "og:image", content: "https://scanner11.lovable.app/surfacescan-cover.jpg" },
      { name: "twitter:image", content: "https://scanner11.lovable.app/surfacescan-cover.jpg" },
    ],
  }),
  component: Index,
});

const SAMPLES = ["github.com", "vercel.com", "cloudflare.com"];

const STAGES = [
  "Resolving DNS zone…",
  "Querying certificate transparency logs…",
  "Enumerating subdomains…",
  "Fingerprinting hosts & open ports…",
  "Crawling pages and headers…",
  "Scoring risk register…",
];

function Index() {
  const [domain, setDomain] = useState("");
  const scan = useServerFn(scanDomain);
  const mutation = useMutation({
    mutationFn: (d: string) => scan({ data: { domain: d } }),
  });

  const run = (d: string) => {
    const target = d.trim();
    if (!target) return;
    setDomain(target);
    mutation.mutate(target);
  };

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 md:py-16">
      <header className="mb-10 text-center">
        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-[11px] uppercase tracking-[0.25em] text-primary">
          <Radar className="size-3.5" />
          Passive recon engine
        </div>
        <h1 className="font-display text-4xl font-bold tracking-tight text-foreground md:text-6xl">
          Map your entire <span className="text-primary">attack surface</span>
        </h1>
        <p className="mx-auto mt-4 max-w-2xl text-sm leading-relaxed text-muted-foreground">
          Enter a domain and SurfaceScan pulls its subdomains, live pages, IP addresses, open ports, known CVEs, DNS
          and email records and HTTP security headers from public sources, then scores everything in one risk register.
        </p>
      </header>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(domain);
        }}
        className="panel glow mx-auto flex max-w-2xl flex-col gap-3 p-3 sm:flex-row"
      >
        <div className="flex flex-1 items-center gap-2 rounded border border-border bg-background/60 px-3">
          <Search className="size-4 text-muted-foreground" />
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="yourcompany.com"
            spellCheck={false}
            aria-label="Domain to scan"
            className="w-full bg-transparent py-3 text-sm text-foreground outline-none placeholder:text-muted-foreground"
          />
        </div>
        <button
          type="submit"
          disabled={mutation.isPending}
          className="inline-flex items-center justify-center gap-2 rounded bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-60"
        >
          {mutation.isPending ? <Loader2 className="size-4 animate-spin" /> : <Radar className="size-4" />}
          {mutation.isPending ? "Scanning" : "Run scan"}
        </button>
      </form>

      <div className="mx-auto mt-3 flex max-w-2xl flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
        <span>Try:</span>
        {SAMPLES.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => run(s)}
            className="rounded border border-border px-2 py-0.5 transition-colors hover:border-primary/50 hover:text-primary"
          >
            {s}
          </button>
        ))}
      </div>

      <div className="mt-10">
        {mutation.isPending ? (
          <div className="panel scanline p-6">
            <div className="mb-5 h-px w-full bg-border">
              <div className="scan-sweep h-px w-1/4 bg-primary" />
            </div>
            <ul className="space-y-2 text-xs text-muted-foreground">
              {STAGES.map((s, i) => (
                <li
                  key={s}
                  className="flex items-center gap-2 animate-pulse"
                  style={{ animationDelay: `${i * 220}ms` }}
                >
                  <Loader2 className="size-3 animate-spin text-primary" />
                  {s}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {mutation.isError ? (
          <div className="panel border-sev-critical/50 p-5 text-sm text-sev-critical">
            Scan failed: {(mutation.error as Error).message}
          </div>
        ) : null}

        {mutation.data && !mutation.isPending ? <ScanReport result={mutation.data} /> : null}
      </div>

      <footer className="mt-16 border-t border-border pt-6 text-center text-[11px] text-muted-foreground">
        <p>
          SurfaceScan · passive intelligence only. Scan domains you own or are authorised to test.
        </p>
        <p className="mt-1.5">
          Made by <span className="font-mono font-semibold text-primary">1315HN01</span>
        </p>
      </footer>
    </main>
  );
}
