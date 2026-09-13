# Architecture

Load this document when choosing which layer a change belongs in.

This package is a hostable MCP server for DNS and network probes. Stdio is the local process
transport. HTTP is Streamable HTTP at `/mcp` plus OAuth at `/authorize`, `/token`, `/register`,
and RFC 9728 metadata. There is no vendor API token.

## Entry points

- `src/index.ts` — CLI: stdio by default, `http` for the listener.
- `src/http-main.ts` — HTTP process. Refuses tokens on argv.
- `src/transport/stdio.ts` — stdio MCP. Uses `MCPNETWORK_NAMESERVERS`. Must not speak OAuth.
  Must not call `readRuntimeConfig`.
- `src/transport/http.ts` — Express app, Host allowlist, health.
- `src/transport/mcp-sessions.ts` — Streamable HTTP session table and sqlite restore.
- `src/auth/persist.ts` — durable OAuth clients, families, codes, CSRF.
- `src/lib/session-store.ts` — AES-GCM sqlite (`node:sqlite`, no extra package).
- `src/auth/routes.ts` — OAuth HTTP surface and consent POST.
- `src/mcp/server.ts` and `src/mcp/catalog.ts` — MCP server and tool catalog.
- `src/auth/login-fields.ts` — the only login-question customization point.
- `src/network/` — DNS, SSL, HTTP, WHOIS, RDAP, CT, RIPEstat, Check-Host. Axios or `node:dns`.
  Inject `lookup`, `reverse`, or `axiosInstance` in tests.

## Catalog

`tsup.config.ts` regenerates `src/mcp/catalog.ts` on build from `src/tools/*/index.ts`. Do not
edit the catalog by hand except to keep tests in sync before a build. Domain order is `account`,
`dns`, `probe`, `checkhost`, `crt`, `ip`.

Tools live in `src/tools/<domain>/index.ts` and call `src/network/`. Runtime
`package.json#dependencies` are `@modelcontextprotocol/sdk`, `express`, `zod`, and `axios`. Do not
use `file:` workspace links.

## Facts that are easy to get wrong

- HTTP Bearer must be an `mcp1.` session token from this host.
- Stdio fakes a local session token. Empty env uses Cloudflare `1.1.1.1` and `1.0.0.1`.
- HTTPS, SVCB, DS, and DNSKEY use DNS-over-HTTPS (`src/network/doh.ts`). Other types use `node:dns`.
- `dns_compare` extra resolvers are appended to Cloudflare, Google, and Quad9.
- `http_probe` accepts only `http:` and `https:`.
- `whois_lookup` fetches RDAP in parallel with port-43 WHOIS. WHOIS follows `refer` /
  `Registrar WHOIS Server` and uses Happy Eyeballs so IPv6 blackholes do not stall on IANA.
- `ssl_check` defaults `rejectUnauthorized` to false. `tcp_connect` and `http_probe` default it to
  true. The caller may set `rejectUnauthorized`, `servername`, `minVersion`, `maxVersion`, `alpn`,
  `requestOcsp`, and `timeoutMs`.
- crt.name `/v1/search` is a subdomain index. Certificate metadata is `crt_certs` (Cert Spotter).
- `src/upstream/client.ts` is the leftover Axios session client required by the MCP server factory.
  Network calls go through `src/network/`.
