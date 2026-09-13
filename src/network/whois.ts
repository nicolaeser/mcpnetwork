import { connect, isIP } from "node:net";
import type { AxiosInstance } from "axios";
import { rdapLookup, type RdapReport } from "./rdap.js";
import { errnoMessage } from "./shape.js";

const IANA = "whois.iana.org";
const MAX_HOPS = 5;

export interface WhoisReport {
  readonly query: string;
  readonly rdap: RdapReport | null;
  readonly rdapError: string | null;
  readonly whoisServer: string;
  readonly whoisServers: string[];
  readonly text: string;
  readonly whoisError: string | null;
}

export async function whoisLookup(
  query: string,
  timeoutMs = 12_000,
  axiosInstance?: AxiosInstance
): Promise<WhoisReport> {
  const q = query.trim();
  const hopMs = Math.min(4_000, Math.max(1_500, Math.floor(timeoutMs / 3)));
  const [rdapSettled, whoisSettled] = await Promise.allSettled([
    rdapLookup(q, axiosInstance),
    followWhois(q, hopMs)
  ]);
  const rdap = rdapSettled.status === "fulfilled" ? rdapSettled.value : null;
  const rdapError = rdapSettled.status === "rejected" ? errnoMessage(rdapSettled.reason) : null;
  const whois = whoisSettled.status === "fulfilled" ? whoisSettled.value : null;
  const whoisError = whoisSettled.status === "rejected" ? errnoMessage(whoisSettled.reason) : (whois?.error ?? null);
  return {
    query: q,
    rdap,
    rdapError,
    whoisServer: whois?.server ?? IANA,
    whoisServers: whois?.servers ?? [IANA],
    text: whois?.text ?? "",
    whoisError
  };
}

export function nextWhoisServer(text: string, current: string): string | undefined {
  const currentHost = normalizeWhoisHost(current);
  const patterns = [
    /^refer:\s*(\S+)/im,
    /^registrar whois server:\s*(\S+)/im,
    /^whois server:\s*(\S+)/im,
    /^whois:\s*(\S+)/im
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    const raw = match?.[1]?.trim();
    if (raw === undefined) continue;
    const host = normalizeWhoisHost(raw);
    if (host === undefined || host === currentHost) continue;
    if (host === IANA && currentHost !== IANA) continue;
    return host;
  }
  return undefined;
}

async function followWhois(
  query: string,
  hopTimeoutMs: number
): Promise<{ server: string; servers: string[]; text: string; error: string | null }> {
  const servers: string[] = [];
  const seen = new Set<string>();
  let server = IANA;
  let text = "";
  let error: string | null = null;
  for (let hop = 0; hop < MAX_HOPS; hop++) {
    if (seen.has(server)) break;
    seen.add(server);
    servers.push(server);
    try {
      text = await whoisQuery(server, query, hopTimeoutMs);
      error = null;
    } catch (err) {
      error = errnoMessage(err);
      break;
    }
    const next = nextWhoisServer(text, server);
    if (next === undefined) break;
    server = next;
  }
  return { server: servers[servers.length - 1] ?? IANA, servers, text, error };
}

function normalizeWhoisHost(value: string): string | undefined {
  let host = value.trim().replace(/\.$/, "").toLowerCase();
  if (host.startsWith("http://") || host.startsWith("https://") || host.startsWith("whois://")) {
    try {
      const url = new URL(host.includes("://") ? host : `https://${host}`);
      host = url.hostname;
    } catch {
      return undefined;
    }
  }
  host = host.replace(/\/.*$/, "");
  if (host.length === 0) return undefined;
  if (isIP(host) !== 0) return host;
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(host)) {
    return undefined;
  }
  return host;
}

function whoisQuery(host: string, query: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = connect({
      host,
      port: 43,
      autoSelectFamily: true,
      autoSelectFamilyAttemptTimeout: 250
    });
    const chunks: Buffer[] = [];
    let settled = false;
    const finish = (error?: Error, body?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error !== undefined) reject(error);
      else resolve(body ?? "");
    };
    const timer = setTimeout(() => finish(new Error(`WHOIS timeout contacting ${host}`)), timeoutMs);
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => socket.write(`${query}\r\n`));
    socket.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    socket.on("end", () => finish(undefined, Buffer.concat(chunks).toString("utf8")));
    socket.on("error", (error) => finish(error));
    socket.on("timeout", () => finish(new Error(`WHOIS timeout contacting ${host}`)));
  });
}
