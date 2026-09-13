import { z } from "zod";
import { defineTool, runTool } from "../../mcp/define-tool.js";
import { probeTcp } from "../../network/tcp.js";
import { probeHttp } from "../../network/http-probe.js";
import { sslCheck } from "../../network/ssl.js";
import { whoisLookup } from "../../network/whois.js";
import { rdapLookup } from "../../network/rdap.js";
import {
  alpnField,
  checkHostnameField,
  expiryWarnDaysField,
  followRedirectsField,
  maxRedirectsField,
  rejectUnauthorizedField,
  requestOcspField,
  servernameField,
  timeoutMsField,
  tlsVersionField
} from "../fields.js";

const tlsFields = {
  rejectUnauthorized: rejectUnauthorizedField,
  servername: servernameField,
  requestOcsp: requestOcspField,
  minVersion: tlsVersionField,
  maxVersion: tlsVersionField,
  alpn: alpnField,
  timeoutMs: timeoutMsField
};

export const tools = [
  defineTool(
    "tcp_connect",
    "TCP connect",
    "TCP connect from this host. Set tls to inspect the leaf certificate and chain. TLS verify defaults to rejectUnauthorized true.",
    z.object({
      host: z.string().min(1),
      port: z.number().int().min(1).max(65535),
      tls: z.boolean().optional(),
      ...tlsFields
    }),
    (ctx, input) =>
      runTool(ctx, () =>
        probeTcp({
          host: input.host,
          port: input.port,
          ...(input.tls === undefined ? {} : { tls: input.tls }),
          ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }),
          ...(input.rejectUnauthorized === undefined ? {} : { rejectUnauthorized: input.rejectUnauthorized }),
          ...(input.servername === undefined ? {} : { servername: input.servername }),
          ...(input.requestOcsp === undefined ? {} : { requestOcsp: input.requestOcsp }),
          ...(input.minVersion === undefined ? {} : { minVersion: input.minVersion }),
          ...(input.maxVersion === undefined ? {} : { maxVersion: input.maxVersion }),
          ...(input.alpn === undefined ? {} : { alpn: input.alpn })
        })
      )
  ),
  defineTool(
    "ssl_check",
    "SSL check",
    "TLS handshake from this host: chain trust, hostname, protocol, cipher, expiry, and OCSP staple. Default port 443. Default rejectUnauthorized false so invalid certificates are reported instead of thrown.",
    z.object({
      host: z.string().min(1),
      port: z.number().int().min(1).max(65535).optional(),
      checkHostname: checkHostnameField,
      expiryWarnDays: expiryWarnDaysField,
      ...tlsFields
    }),
    (ctx, input) =>
      runTool(ctx, () =>
        sslCheck({
          host: input.host,
          ...(input.port === undefined ? {} : { port: input.port }),
          ...(input.servername === undefined ? {} : { servername: input.servername }),
          ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs }),
          ...(input.rejectUnauthorized === undefined ? {} : { rejectUnauthorized: input.rejectUnauthorized }),
          ...(input.requestOcsp === undefined ? {} : { requestOcsp: input.requestOcsp }),
          ...(input.checkHostname === undefined ? {} : { checkHostname: input.checkHostname }),
          ...(input.expiryWarnDays === undefined ? {} : { expiryWarnDays: input.expiryWarnDays }),
          ...(input.minVersion === undefined ? {} : { minVersion: input.minVersion }),
          ...(input.maxVersion === undefined ? {} : { maxVersion: input.maxVersion }),
          ...(input.alpn === undefined ? {} : { alpn: input.alpn })
        })
      )
  ),
  defineTool(
    "http_probe",
    "HTTP probe",
    "HTTP or HTTPS request from this host with timing, status, and redirect hops. Body is capped. HTTPS verify defaults to rejectUnauthorized true.",
    z.object({
      url: z.string().min(1),
      method: z.string().optional(),
      followRedirects: followRedirectsField,
      maxRedirects: maxRedirectsField,
      rejectUnauthorized: rejectUnauthorizedField,
      timeoutMs: timeoutMsField
    }),
    (ctx, input) =>
      runTool(ctx, () =>
        probeHttp({
          url: input.url,
          ...(input.method === undefined ? {} : { method: input.method }),
          ...(input.followRedirects === undefined ? {} : { followRedirects: input.followRedirects }),
          ...(input.maxRedirects === undefined ? {} : { maxRedirects: input.maxRedirects }),
          ...(input.rejectUnauthorized === undefined ? {} : { rejectUnauthorized: input.rejectUnauthorized }),
          ...(input.timeoutMs === undefined ? {} : { timeoutMs: input.timeoutMs })
        })
      )
  ),
  defineTool(
    "whois_lookup",
    "WHOIS",
    "Registration data. RDAP is preferred for full domain records (registrar, dates, nameservers). WHOIS follows IANA to the registry and registrar; port 43 is often thin or stuck at IANA.",
    z.object({
      query: z.string().min(1),
      timeoutMs: timeoutMsField
    }),
    (ctx, input) =>
      runTool(ctx, () => whoisLookup(input.query, input.timeoutMs ?? 12_000))
  ),
  defineTool(
    "rdap_lookup",
    "RDAP",
    "Registration data for a domain or IP via rdap.org. No API key.",
    z.object({ query: z.string().min(1) }),
    (ctx, input) => runTool(ctx, () => rdapLookup(input.query))
  )
];
