# SurfaceScan

Passive attack-surface scanner. Enter a domain and SurfaceScan collects:

- subdomains from public certificate transparency logs and a DNS sweep
- reachable pages, including paths found in `robots.txt`, `sitemap.xml` and a sensitive-path probe
- IP addresses, open ports and known CVEs from public fingerprint indexes
- DNS records, WHOIS/RDAP registration data and HTTP security headers
- a scored risk register with severities and remediation notes

All data comes from public sources. No intrusive probing is performed. Only scan
domains you own or are authorised to test.

## Development

Requires Node.js and npm.

```sh
npm install
npm run dev
```

Build for production:

```sh
npm run build
```

Made by 1315HN01.
