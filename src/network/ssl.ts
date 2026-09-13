import { isIP } from "node:net";
import { connect as tlsConnect, type DetailedPeerCertificate, type TLSSocket } from "node:tls";
import { X509Certificate } from "node:crypto";
import {
  resolveTlsHandshakeOptions,
  type TlsHandshakeOptions,
  type TlsVersion
} from "./tls-options.js";

const WEAK_CIPHER = /(?:NULL|EXPORT|DES|RC4|MD5|PSK|aNULL|eNULL|3DES)/i;
const OLD_PROTOCOL = new Set(["SSLv3", "TLSv1", "TLSv1.1"]);
const EXPIRY_WARN_DAYS = 21;

export interface SslSan {
  readonly dns: string[];
  readonly ip: string[];
  readonly email: string[];
}

export interface SslCertView {
  readonly subject: string;
  readonly issuer: string;
  readonly validFrom: string;
  readonly validTo: string;
  readonly daysLeft: number | null;
  readonly fingerprint256: string;
  readonly serialNumber: string;
  readonly san: SslSan;
  readonly keyType: string | null;
}

export interface SslCipher {
  readonly name: string;
  readonly standardName: string | null;
  readonly version: string | null;
}

export type SslSeverity = "error" | "warning";

export interface SslIssue {
  readonly severity: SslSeverity;
  readonly code: string;
  readonly message: string;
}

export interface SslSnapshot {
  readonly host: string;
  readonly port: number;
  readonly sni: string | null;
  readonly authorized: boolean;
  readonly authorizationError: string | null;
  readonly protocol: string | null;
  readonly alpn: string | null;
  readonly cipher: SslCipher | null;
  readonly ocspStapled: boolean;
  readonly hostnameMatch: boolean | null;
  readonly certificate: SslCertView | null;
  readonly chain: SslCertView[];
}

export interface SslSettings {
  readonly rejectUnauthorized: boolean;
  readonly requestOcsp: boolean;
  readonly checkHostname: boolean;
  readonly expiryWarnDays: number;
  readonly minVersion: TlsVersion | null;
  readonly maxVersion: TlsVersion | null;
  readonly alpn: string[];
}

export const DEFAULT_SSL_SETTINGS: SslSettings = {
  rejectUnauthorized: false,
  requestOcsp: true,
  checkHostname: true,
  expiryWarnDays: 21,
  minVersion: null,
  maxVersion: null,
  alpn: ["h2", "http/1.1"]
};

export interface SslCheckReport extends SslSnapshot {
  readonly ok: boolean;
  readonly ms: number;
  readonly issues: SslIssue[];
  readonly settings: SslSettings;
}

export function resolveSslSettings(input: {
  readonly rejectUnauthorized?: boolean;
  readonly requestOcsp?: boolean;
  readonly checkHostname?: boolean;
  readonly expiryWarnDays?: number;
  readonly minVersion?: TlsVersion;
  readonly maxVersion?: TlsVersion;
  readonly alpn?: readonly string[];
}): SslSettings {
  const handshake = resolveTlsHandshakeOptions(input, { rejectUnauthorized: false });
  return {
    rejectUnauthorized: handshake.rejectUnauthorized,
    requestOcsp: handshake.requestOcsp,
    checkHostname: input.checkHostname !== false,
    expiryWarnDays: input.expiryWarnDays ?? EXPIRY_WARN_DAYS,
    minVersion: handshake.minVersion ?? null,
    maxVersion: handshake.maxVersion ?? null,
    alpn: [...handshake.alpn]
  };
}

export async function sslCheck(input: {
  readonly host: string;
  readonly port?: number;
  readonly servername?: string;
  readonly timeoutMs?: number;
  readonly rejectUnauthorized?: boolean;
  readonly requestOcsp?: boolean;
  readonly checkHostname?: boolean;
  readonly expiryWarnDays?: number;
  readonly minVersion?: TlsVersion;
  readonly maxVersion?: TlsVersion;
  readonly alpn?: readonly string[];
}): Promise<SslCheckReport> {
  const host = input.host.trim();
  const port = input.port ?? 443;
  const timeoutMs = input.timeoutMs ?? 10_000;
  const settings = resolveSslSettings(input);
  const sni =
    input.servername?.trim() ||
    (isIP(host) === 0 ? host : "");
  const started = Date.now();
  const handshake = resolveTlsHandshakeOptions(
    {
      ...input,
      ...(sni.length > 0 ? { servername: sni } : {})
    },
    { rejectUnauthorized: false }
  );
  const { socket, ocspStapled } = await connectTls({
    host,
    port,
    timeoutMs,
    handshake
  });
  try {
    const leaf = socket.getPeerCertificate(true);
    const chain = certChain(leaf);
    const x509 = peerX509(socket);
    const certificate = chain[0] ?? (x509 === undefined ? null : viewX509(x509));
    const snapshot: SslSnapshot = {
      host,
      port,
      sni: sni.length > 0 ? sni : null,
      authorized: socket.authorized,
      authorizationError: socket.authorizationError === undefined ? null : String(socket.authorizationError),
      protocol: protocolName(socket.getProtocol()),
      alpn: alpnName(socket.alpnProtocol),
      cipher: viewCipher(socket.getCipher()),
      ocspStapled,
      hostnameMatch: hostnameMatch(host, sni, x509, certificate),
      certificate,
      chain
    };
    return evaluateSsl(snapshot, Date.now() - started, settings);
  } finally {
    socket.end();
  }
}

export function evaluateSsl(
  snapshot: SslSnapshot,
  ms: number,
  settings: SslSettings = DEFAULT_SSL_SETTINGS,
  now = Date.now()
): SslCheckReport {
  const issues: SslIssue[] = [];
  if (!snapshot.authorized) {
    issues.push({
      severity: "error",
      code: "untrusted_chain",
      message: snapshot.authorizationError ?? "Certificate chain was not trusted."
    });
  }
  if (settings.checkHostname && snapshot.hostnameMatch === false) {
    issues.push({
      severity: "error",
      code: "hostname_mismatch",
      message: `Certificate does not match ${snapshot.sni ?? snapshot.host}.`
    });
  }
  const protocol = snapshot.protocol;
  if (protocol !== null && OLD_PROTOCOL.has(protocol)) {
    issues.push({
      severity: "error",
      code: "old_protocol",
      message: `Negotiated ${protocol}.`
    });
  }
  const cipherName = snapshot.cipher?.name ?? snapshot.cipher?.standardName;
  if (typeof cipherName === "string" && WEAK_CIPHER.test(cipherName)) {
    issues.push({
      severity: "error",
      code: "weak_cipher",
      message: `Weak cipher ${cipherName}.`
    });
  }
  const cert = snapshot.certificate;
  if (cert === null) {
    issues.push({ severity: "error", code: "no_certificate", message: "Peer sent no certificate." });
  } else {
    issues.push(...validityIssues(cert, now, settings.expiryWarnDays));
  }
  return {
    ...snapshot,
    ok: issues.every((item) => item.severity !== "error"),
    ms,
    issues,
    settings
  };
}

export function parseSubjectAltName(value: string | null | undefined): SslSan {
  const dns: string[] = [];
  const ip: string[] = [];
  const email: string[] = [];
  if (value === undefined || value === null || value.length === 0) return { dns, ip, email };
  for (const part of value.split(/,\s*/)) {
    const [kind, ...rest] = part.split(":");
    const name = rest.join(":").trim();
    if (name.length === 0) continue;
    const key = (kind ?? "").trim().toLowerCase();
    if (key === "dns") dns.push(name.toLowerCase());
    else if (key === "ip address" || key === "ip") ip.push(name);
    else if (key === "email") email.push(name);
  }
  return { dns, ip, email };
}

export function nameMatchesSan(host: string, san: SslSan): boolean {
  if (isIP(host) !== 0) return san.ip.includes(host);
  const name = host.replace(/\.$/, "").toLowerCase();
  for (const dns of san.dns) {
    if (dns === name) return true;
    if (dns.startsWith("*.") && wildcardMatches(dns, name)) return true;
  }
  return false;
}

function validityIssues(cert: SslCertView, now: number, expiryWarnDays: number): SslIssue[] {
  const issues: SslIssue[] = [];
  const from = Date.parse(cert.validFrom);
  const to = Date.parse(cert.validTo);
  if (Number.isFinite(from) && now < from) {
    issues.push({ severity: "error", code: "not_yet_valid", message: `Not valid before ${cert.validFrom}.` });
  }
  if (cert.daysLeft !== null && cert.daysLeft < 0) {
    issues.push({ severity: "error", code: "expired", message: `Expired on ${cert.validTo}.` });
  } else if (expiryWarnDays > 0 && cert.daysLeft !== null && cert.daysLeft < expiryWarnDays) {
    issues.push({
      severity: "warning",
      code: "expires_soon",
      message: `Expires in ${cert.daysLeft} day(s) (${cert.validTo}).`
    });
  } else if (!Number.isFinite(to) && cert.daysLeft === null) {
    issues.push({ severity: "warning", code: "no_expiry", message: "Could not parse certificate expiry." });
  }
  return issues;
}

function wildcardMatches(pattern: string, name: string): boolean {
  const suffix = pattern.slice(1);
  if (!name.endsWith(suffix)) return false;
  const rest = name.slice(0, name.length - suffix.length);
  return rest.length > 0 && !rest.includes(".");
}

function hostnameMatch(
  host: string,
  sni: string,
  x509: X509Certificate | undefined,
  certificate: SslCertView | null
): boolean | null {
  const name = sni.length > 0 ? sni : host;
  if (isIP(name) !== 0) {
    if (x509 !== undefined) {
      try {
        return x509.checkIP(name) !== undefined;
      } catch {
        return certificate === null ? null : nameMatchesSan(name, certificate.san);
      }
    }
    return certificate === null ? null : nameMatchesSan(name, certificate.san);
  }
  if (x509 !== undefined) {
    try {
      return x509.checkHost(name) !== undefined;
    } catch {
      return certificate === null ? null : nameMatchesSan(name, certificate.san);
    }
  }
  return certificate === null ? null : nameMatchesSan(name, certificate.san);
}

function connectTls(input: {
  readonly host: string;
  readonly port: number;
  readonly timeoutMs: number;
  readonly handshake: TlsHandshakeOptions;
}): Promise<{ socket: TLSSocket; ocspStapled: boolean }> {
  return new Promise((resolve, reject) => {
    let ocspStapled = false;
    const handshake = input.handshake;
    const socket = tlsConnect({
      host: input.host,
      port: input.port,
      timeout: input.timeoutMs,
      rejectUnauthorized: handshake.rejectUnauthorized,
      requestOCSP: handshake.requestOcsp,
      ...(handshake.servername === undefined ? {} : { servername: handshake.servername }),
      ...(handshake.minVersion === undefined ? {} : { minVersion: handshake.minVersion }),
      ...(handshake.maxVersion === undefined ? {} : { maxVersion: handshake.maxVersion }),
      ...(handshake.alpn.length === 0 ? {} : { ALPNProtocols: [...handshake.alpn] })
    });
    const onErr = (error: Error) => {
      socket.destroy();
      reject(error);
    };
    socket.once("OCSPResponse", () => {
      ocspStapled = true;
    });
    socket.once("secureConnect", () => {
      socket.off("error", onErr);
      resolve({ socket, ocspStapled });
    });
    socket.once("error", onErr);
    socket.once("timeout", () => onErr(new Error("TLS connect timeout")));
  });
}

function peerX509(socket: TLSSocket): X509Certificate | undefined {
  try {
    return socket.getPeerX509Certificate();
  } catch {
    return undefined;
  }
}

function certChain(leaf: DetailedPeerCertificate): SslCertView[] {
  const chain: SslCertView[] = [];
  const seen = new Set<string>();
  let cert: DetailedPeerCertificate | undefined = leaf;
  while (cert !== undefined && Object.keys(cert).length > 0) {
    const fp = cert.fingerprint256 || cert.fingerprint || String(chain.length);
    if (seen.has(fp)) break;
    seen.add(fp);
    chain.push(viewPeer(cert));
    const next: DetailedPeerCertificate | undefined = cert.issuerCertificate;
    if (next === undefined || next === cert) break;
    cert = next;
  }
  return chain;
}

function viewPeer(cert: DetailedPeerCertificate): SslCertView {
  return {
    subject: formatName(cert.subject),
    issuer: formatName(cert.issuer),
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    daysLeft: daysLeft(cert.valid_to),
    fingerprint256: cert.fingerprint256,
    serialNumber: cert.serialNumber,
    san: parseSubjectAltName(cert.subjectaltname),
    keyType: null
  };
}

function viewX509(cert: X509Certificate): SslCertView {
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    daysLeft: daysLeft(cert.validToDate.toISOString()),
    fingerprint256: cert.fingerprint256,
    serialNumber: cert.serialNumber,
    san: parseSubjectAltName(cert.subjectAltName),
    keyType: cert.publicKey.asymmetricKeyType ?? null
  };
}

function formatName(name: DetailedPeerCertificate["subject"]): string {
  const cn = name.CN;
  if (typeof cn === "string" && cn.length > 0) return cn;
  const parts = Object.entries(name)
    .filter(([, value]) => typeof value === "string" && value.length > 0)
    .map(([key, value]) => `${key}=${value}`);
  return parts.join(", ");
}

function daysLeft(validTo: string): number | null {
  const to = Date.parse(validTo);
  if (!Number.isFinite(to)) return null;
  return Math.floor((to - Date.now()) / 86_400_000);
}

function protocolName(value: string | false | null): string | null {
  if (value === false || value === null || value.length === 0) return null;
  return value;
}

function alpnName(value: string | false | null): string | null {
  if (value === false || value === null || value.length === 0) return null;
  return value;
}

function viewCipher(cipher: ReturnType<TLSSocket["getCipher"]> | undefined): SslCipher | null {
  if (cipher === undefined) return null;
  return {
    name: cipher.name,
    standardName: cipher.standardName.length > 0 ? cipher.standardName : null,
    version: cipher.version.length > 0 ? cipher.version : null
  };
}
