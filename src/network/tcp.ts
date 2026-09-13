import { connect as tcpConnect, isIP } from "node:net";
import {
  connect as tlsConnect,
  type ConnectionOptions,
  type DetailedPeerCertificate,
  type TLSSocket
} from "node:tls";
import { resolveTlsHandshakeOptions, type TlsHandshakeOptions, type TlsVersion } from "./tls-options.js";

export interface TlsCertView {
  readonly subject: DetailedPeerCertificate["subject"];
  readonly issuer: DetailedPeerCertificate["issuer"];
  readonly validFrom: string;
  readonly validTo: string;
  readonly daysLeft: number | null;
  readonly fingerprint256: string;
  readonly serialNumber: string;
  readonly subjectaltname: string | null;
}

export interface TcpConnectReport {
  readonly host: string;
  readonly port: number;
  readonly tls: false;
  readonly ok: true;
  readonly ms: number;
}

export interface TlsInspectReport {
  readonly host: string;
  readonly port: number;
  readonly tls: true;
  readonly authorized: boolean;
  readonly authorizationError: string | null;
  readonly protocol: string | false | null;
  readonly alpn: string | false | null;
  readonly ms: number;
  readonly certificate: TlsCertView | null;
  readonly chain: TlsCertView[];
  readonly daysLeft: number | null;
  readonly rejectUnauthorized: boolean;
}

export type TcpProbeReport = TcpConnectReport | TlsInspectReport;

export async function probeTcp(input: {
  readonly host: string;
  readonly port: number;
  readonly tls?: boolean;
  readonly timeoutMs?: number;
  readonly rejectUnauthorized?: boolean;
  readonly servername?: string;
  readonly requestOcsp?: boolean;
  readonly minVersion?: TlsVersion;
  readonly maxVersion?: TlsVersion;
  readonly alpn?: readonly string[];
}): Promise<TcpProbeReport> {
  const timeoutMs = input.timeoutMs ?? 8_000;
  const started = Date.now();
  if (input.tls === true) {
    const sni = input.servername?.trim() || (isIP(input.host) === 0 ? input.host : "");
    const handshake = resolveTlsHandshakeOptions(
      {
        ...(input.rejectUnauthorized === undefined ? {} : { rejectUnauthorized: input.rejectUnauthorized }),
        ...(input.requestOcsp === undefined ? {} : { requestOcsp: input.requestOcsp }),
        ...(input.minVersion === undefined ? {} : { minVersion: input.minVersion }),
        ...(input.maxVersion === undefined ? {} : { maxVersion: input.maxVersion }),
        ...(input.alpn === undefined ? {} : { alpn: input.alpn }),
        ...(sni.length > 0 ? { servername: sni } : {})
      },
      { rejectUnauthorized: true }
    );
    const socket = await new Promise<TLSSocket>((resolve, reject) => {
      const tls = tlsConnect(tlsConnectOptions(input.host, input.port, timeoutMs, handshake));
      const onErr = (error: Error) => {
        tls.destroy();
        reject(error);
      };
      tls.once("secureConnect", () => {
        tls.off("error", onErr);
        resolve(tls);
      });
      tls.once("error", onErr);
      tls.once("timeout", () => onErr(new Error("TLS connect timeout")));
    });
    const leaf = socket.getPeerCertificate(true);
    const chain = certChain(leaf);
    const ms = Date.now() - started;
    socket.end();
    return {
      host: input.host,
      port: input.port,
      tls: true,
      authorized: socket.authorized,
      authorizationError: socket.authorizationError === undefined ? null : String(socket.authorizationError),
      protocol: socket.getProtocol(),
      alpn: socket.alpnProtocol,
      ms,
      certificate: chain[0] ?? null,
      chain,
      daysLeft: chain[0]?.daysLeft ?? null,
      rejectUnauthorized: handshake.rejectUnauthorized
    };
  }
  await new Promise<void>((resolve, reject) => {
    const socket = tcpConnect({ host: input.host, port: input.port, timeout: timeoutMs });
    const onErr = (error: Error) => {
      socket.destroy();
      reject(error);
    };
    socket.once("connect", () => {
      socket.off("error", onErr);
      socket.end();
      resolve();
    });
    socket.once("error", onErr);
    socket.once("timeout", () => onErr(new Error("TCP connect timeout")));
  });
  return { host: input.host, port: input.port, tls: false, ms: Date.now() - started, ok: true };
}

function tlsConnectOptions(
  host: string,
  port: number,
  timeoutMs: number,
  handshake: TlsHandshakeOptions
): ConnectionOptions {
  return {
    host,
    port,
    timeout: timeoutMs,
    rejectUnauthorized: handshake.rejectUnauthorized,
    requestOCSP: handshake.requestOcsp,
    ...(handshake.servername === undefined ? {} : { servername: handshake.servername }),
    ...(handshake.minVersion === undefined ? {} : { minVersion: handshake.minVersion }),
    ...(handshake.maxVersion === undefined ? {} : { maxVersion: handshake.maxVersion }),
    ...(handshake.alpn.length === 0 ? {} : { ALPNProtocols: [...handshake.alpn] })
  };
}

function certChain(leaf: DetailedPeerCertificate): TlsCertView[] {
  const chain: TlsCertView[] = [];
  const seen = new Set<string>();
  let cert: DetailedPeerCertificate | undefined = leaf;
  while (cert !== undefined && Object.keys(cert).length > 0) {
    const fp = cert.fingerprint256 || cert.fingerprint || String(chain.length);
    if (seen.has(fp)) break;
    seen.add(fp);
    chain.push(viewCert(cert));
    const next: DetailedPeerCertificate | undefined = cert.issuerCertificate;
    if (next === undefined || next === cert) break;
    cert = next;
  }
  return chain;
}

function viewCert(cert: DetailedPeerCertificate): TlsCertView {
  const validTo = cert.valid_to.length > 0 ? Date.parse(cert.valid_to) : Number.NaN;
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    daysLeft: Number.isFinite(validTo) ? Math.floor((validTo - Date.now()) / 86_400_000) : null,
    fingerprint256: cert.fingerprint256,
    serialNumber: cert.serialNumber,
    subjectaltname: cert.subjectaltname ?? null
  };
}
