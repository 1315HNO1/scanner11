# Remove AI / builder fingerprints from the site

Goal: nothing a visitor, crawler, or "was this vibe-coded?" detector sees should hint at the tool that built the site, and the page copy should not read like default AI output.

## What visitors and crawlers currently see

1. Page title is still the placeholder **"Lovable App"** in the shared page metadata, plus `author: Lovable` and `twitter:site: @Lovable`.
2. The social preview image points at a `*.lovable.app` screenshot URL.
3. A small builder badge is shown on the published site.
4. Site description and share text in metadata repeat the generic default wording.
5. An error-reporting snippet ships with the page and carries builder-specific names in the shipped code.
6. The project README links back to the builder and the `scanner11.lovable.app` address.

## Changes

**Shared page metadata**
- Title: "SurfaceScan — Attack Surface & Subdomain Scanner"; author: "1315HN01"; drop the `@Lovable` Twitter handle.
- Replace the share-preview image with a self-hosted one served from the site's own domain, or drop the image tags entirely if no own-domain image exists yet (hosting still generates a preview).
- Keep the per-page title/description on the home page as they are — they are already product-specific.

**Published badge**
- Turn off the builder badge on the published site.

**Error reporting**
- Remove the error-reporting import and call from the root layout and delete the module, so no builder-specific identifiers appear in the shipped JavaScript. Errors still show the friendly error screen; only the editor's error telemetry is lost.

**README**
- Rewrite as a normal project README: what SurfaceScan does, how to run it locally. No builder links, no `*.lovable.app` address.

**Copy pass (optional but recommended)**
- Light edit of the hero and report wording to cut the telltale generic-AI rhythm (heavy em dashes, "comprehensive", triple-item lists). Same meaning, plainer voice.

## Notes / limits

- Nothing can guarantee a detector's verdict; these steps remove the concrete, checkable signals (metadata, badge, shipped identifiers, links).
- The published address itself (`scanner11.lovable.app`) is the biggest remaining giveaway. A custom domain is the only way to remove it — say the word and I'll walk through connecting one.
- Build tooling in `package.json` / `vite.config.ts` is not visible to visitors and is required for the app to build, so it stays.
