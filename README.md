# mcpnetwork

DNS, WHOIS, RDAP, SSL, HTTP probes, Certificate Transparency, and Check-Host. Stdio or HTTP at `/mcp`.

```sh
mcpnetwork
mcpnetwork http
```

Default resolvers are Cloudflare `1.1.1.1` and `1.0.0.1`. Override per call or with `MCPNETWORK_NAMESERVERS`. No upstream API key. DNS, TCP, SSL, and HTTP probes run from this host.

HTTP is OAuth. Secrets stay on this host.

Env: `MCPNETWORK_NAMESERVERS`, `MCP_OAUTH_SECRET`, `MCP_PUBLIC_URL`, `MCP_AUTH_PASSWORD`.

`main` publishes GHCR `:latest`. `development` publishes `:dev`.

### Connection page

The consent page identifies the requesting application and explains this connector’s purpose.
Only account details needed for sign-in are shown upfront; optional settings expand on demand.
Server access, when required, is a separate step. Light and dark themes follow your device.
