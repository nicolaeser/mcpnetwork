import { z } from "zod";
import { TLS_VERSIONS } from "../network/tls-options.js";

export const timeoutMsField = z
  .number()
  .int()
  .min(200)
  .max(60_000)
  .optional()
  .describe("Deadline in milliseconds.");

export const rejectUnauthorizedField = z
  .boolean()
  .optional()
  .describe(
    "Verify the TLS certificate with the system CA store. false continues the handshake and reports authorized=false instead of throwing."
  );

export const servernameField = z
  .string()
  .min(1)
  .optional()
  .describe("TLS SNI. Defaults to host when host is not an IP.");

export const requestOcspField = z
  .boolean()
  .optional()
  .describe("Request an OCSP staple in ClientHello. Default true.");

export const tlsVersionField = z
  .enum(TLS_VERSIONS)
  .optional()
  .describe("TLS version bound passed to Node (TLSv1 through TLSv1.3).");

export const alpnField = z
  .array(z.string().min(1).max(32))
  .max(8)
  .optional()
  .describe('ALPN protocols to offer, e.g. ["h2","http/1.1"]. Empty list offers none.');

export const followRedirectsField = z
  .boolean()
  .optional()
  .describe("Follow HTTP redirects. Default true.");

export const maxRedirectsField = z
  .number()
  .int()
  .min(0)
  .max(10)
  .optional()
  .describe("Max redirect hops when followRedirects is true. Default 6.");

export const waitField = z.boolean().optional().describe("Wait for Check-Host results. Default true.");

export const waitTimeoutMsField = z
  .number()
  .int()
  .min(500)
  .max(60_000)
  .optional()
  .describe("How long to poll Check-Host when wait is true. Default 20000.");

export const expiryWarnDaysField = z
  .number()
  .int()
  .min(0)
  .max(365)
  .optional()
  .describe("Warn when the certificate expires within this many days. Default 21. 0 disables the warning.");

export const checkHostnameField = z
  .boolean()
  .optional()
  .describe("Treat hostname/SNI mismatch as an error. Default true.");
