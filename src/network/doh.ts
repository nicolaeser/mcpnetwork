import axios, { type AxiosInstance } from "axios";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";
import { asBoolean, asFiniteNumber, asRecord, asString, asUnknownArray } from "./shape.js";

export const DOH_TYPES = ["HTTPS", "SVCB", "DS", "DNSKEY", "RRSIG"] as const;
export type DohType = (typeof DOH_TYPES)[number];

export interface DohRecord {
  readonly data: string;
  readonly ttl?: number;
  readonly type?: number;
}

export interface DohLookupResult {
  readonly records: DohRecord[];
  readonly ad: boolean;
}

const CLOUDFLARE_DOH = "https://cloudflare-dns.com/dns-query";

const DOH_BY_IP: Readonly<Record<string, string>> = {
  "1.1.1.1": CLOUDFLARE_DOH,
  "1.0.0.1": CLOUDFLARE_DOH,
  "8.8.8.8": "https://dns.google/resolve",
  "8.8.4.4": "https://dns.google/resolve",
  "9.9.9.9": "https://dns.quad9.net:5053/dns-query"
};

const DOH_TYPE_SET: ReadonlySet<string> = new Set(DOH_TYPES);

export function isDohType(type: string): type is DohType {
  return DOH_TYPE_SET.has(type);
}

export function dohEndpoint(nameserver: string | undefined): string {
  if (nameserver === undefined) return CLOUDFLARE_DOH;
  return DOH_BY_IP[nameserver] ?? CLOUDFLARE_DOH;
}

export function createDohClient(axiosInstance?: AxiosInstance): AxiosInstance {
  return (
    axiosInstance ??
    axios.create({
      timeout: 10_000,
      headers: {
        Accept: "application/dns-json",
        "User-Agent": `${PACKAGE_NAME}/${PACKAGE_VERSION}`
      }
    })
  );
}

export async function dohLookup(
  name: string,
  type: string,
  servers: readonly string[],
  axiosInstance?: AxiosInstance
): Promise<DohLookupResult> {
  const client = createDohClient(axiosInstance);
  const response = await client.get<unknown>(dohEndpoint(servers[0]), { params: { name, type } });
  const body = asRecord(response.data) ?? {};
  const status = asFiniteNumber(body.Status) ?? 0;
  const answers = asUnknownArray(body.Answer).flatMap(parseDohAnswer);
  if (status === 3) {
    throw Object.assign(new Error(`NXDOMAIN ${name}`), { code: "ENOTFOUND" });
  }
  if (status !== 0 && answers.length === 0) {
    throw Object.assign(new Error(`DoH status ${status}`), { code: "ENODATA" });
  }
  if (answers.length === 0) {
    throw Object.assign(new Error(`No ${type} records`), { code: "ENODATA" });
  }
  return { ad: asBoolean(body.AD) === true, records: answers };
}

function parseDohAnswer(value: unknown): DohRecord[] {
  const rec = asRecord(value);
  const data = rec === undefined ? undefined : asString(rec.data);
  if (data === undefined) return [];
  const ttl = rec === undefined ? undefined : asFiniteNumber(rec.TTL);
  const type = rec === undefined ? undefined : asFiniteNumber(rec.type);
  return [
    {
      data,
      ...(ttl === undefined ? {} : { ttl }),
      ...(type === undefined ? {} : { type })
    }
  ];
}
