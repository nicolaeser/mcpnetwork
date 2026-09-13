import axios, { type AxiosInstance } from "axios";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";
import { asBoolean, asRecord, asString, asStringArray, asUnknownArray } from "./shape.js";

export interface CrtNameRow {
  readonly sub: string;
  readonly firstSeen: string | null;
}

export interface CrtNameFilter {
  readonly contains?: string;
  readonly since?: string;
  readonly limit: number;
}

export interface CrtNameReport {
  readonly source: "crt.name";
  readonly apex: string;
  readonly total: number;
  readonly returned: number;
  readonly earliest: string | null;
  readonly latest: string | null;
  readonly wildcards: number;
  readonly names: CrtNameRow[];
}

export interface CertIssuance {
  readonly id: string;
  readonly dnsNames: string[];
  readonly notBefore: string | null;
  readonly notAfter: string | null;
  readonly revoked: boolean | null;
  readonly certSha256: string | null;
  readonly pubkeySha256: string | null;
  readonly issuer: string | null;
}

export interface CrtIssuanceReport {
  readonly source: "certspotter";
  readonly domain: string;
  readonly total: number;
  readonly returned: number;
  readonly items: CertIssuance[];
}

export function createCrtNameClient(axiosInstance?: AxiosInstance): AxiosInstance {
  return (
    axiosInstance ??
    axios.create({
      baseURL: "https://crt.name",
      timeout: 20_000,
      maxContentLength: 8_000_000,
      headers: {
        Accept: "application/json",
        "User-Agent": `${PACKAGE_NAME}/${PACKAGE_VERSION}`
      }
    })
  );
}

export function createCertspotterClient(axiosInstance?: AxiosInstance): AxiosInstance {
  return (
    axiosInstance ??
    axios.create({
      baseURL: "https://api.certspotter.com",
      timeout: 20_000,
      headers: {
        Accept: "application/json",
        "User-Agent": `${PACKAGE_NAME}/${PACKAGE_VERSION}`
      }
    })
  );
}

export function filterCrtName(rows: readonly CrtNameRow[], options: CrtNameFilter): Omit<CrtNameReport, "source" | "apex"> {
  const needle = options.contains?.trim().toLowerCase();
  const since = options.since?.trim();
  const filtered = rows.filter((row) => {
    if (needle !== undefined && needle.length > 0 && !row.sub.toLowerCase().includes(needle)) return false;
    if (since !== undefined && since.length > 0) {
      if (row.firstSeen === null) return false;
      return row.firstSeen >= since;
    }
    return true;
  });
  const dated = filtered
    .map((row) => row.firstSeen)
    .filter((value): value is string => value !== null)
    .sort();
  const names = filtered.slice(0, options.limit);
  return {
    total: filtered.length,
    returned: names.length,
    earliest: dated[0] ?? null,
    latest: dated[dated.length - 1] ?? null,
    wildcards: filtered.filter((row) => row.sub.startsWith("*")).length,
    names
  };
}

export async function crtNameSearch(
  input: {
    readonly apex: string;
    readonly contains?: string;
    readonly since?: string;
    readonly limit?: number;
  },
  axiosInstance?: AxiosInstance
): Promise<CrtNameReport> {
  const apex = input.apex.replace(/\.$/, "").toLowerCase();
  const limit = Math.min(Math.max(input.limit ?? 200, 1), 2_000);
  const client = createCrtNameClient(axiosInstance);
  const response = await client.get<unknown>("/v1/search", {
    params: { apex, format: "json", dates: "1" }
  });
  return {
    source: "crt.name",
    apex,
    ...filterCrtName(parseCrtName(response.data), {
      limit,
      ...(input.contains === undefined ? {} : { contains: input.contains }),
      ...(input.since === undefined ? {} : { since: input.since })
    })
  };
}

export async function crtIssuances(
  input: {
    readonly domain: string;
    readonly includeSubdomains?: boolean;
    readonly matchWildcards?: boolean;
    readonly after?: string;
    readonly limit?: number;
  },
  axiosInstance?: AxiosInstance
): Promise<CrtIssuanceReport> {
  const domain = input.domain.replace(/\.$/, "").toLowerCase();
  const limit = Math.min(Math.max(input.limit ?? 25, 1), 100);
  const client = createCertspotterClient(axiosInstance);
  const response = await client.get<unknown>("/v1/issuances", {
    params: {
      domain,
      include_subdomains: input.includeSubdomains === false ? "false" : "true",
      match_wildcards: input.matchWildcards === true ? "true" : "false",
      expand: "dns_names,issuer",
      ...(input.after === undefined || input.after.length === 0 ? {} : { after: input.after })
    }
  });
  const rows = asUnknownArray(response.data).flatMap(parseIssuance);
  const items = rows.slice(0, limit);
  return { source: "certspotter", domain, total: rows.length, returned: items.length, items };
}

export function parseCrtName(data: unknown): CrtNameRow[] {
  const rows: CrtNameRow[] = [];
  for (const item of asUnknownArray(data)) {
    if (typeof item === "string") {
      rows.push({ sub: item, firstSeen: null });
      continue;
    }
    const rec = asRecord(item);
    const sub = rec === undefined ? undefined : asString(rec.sub);
    if (sub === undefined) continue;
    const seen = rec === undefined ? undefined : rec.first_seen;
    rows.push({ sub, firstSeen: typeof seen === "string" ? seen : null });
  }
  return rows;
}

export function parseIssuance(value: unknown): CertIssuance[] {
  const rec = asRecord(value);
  const id = rec === undefined ? undefined : asString(rec.id) ?? (typeof rec.id === "number" ? String(rec.id) : undefined);
  if (id === undefined) return [];
  const issuerRec = rec === undefined ? undefined : asRecord(rec.issuer);
  const issuer =
    issuerRec === undefined
      ? (rec === undefined ? null : (asString(rec.issuer) ?? null))
      : (asString(issuerRec.friendly_name) ?? asString(issuerRec.name) ?? null);
  return [
    {
      id,
      dnsNames: rec === undefined ? [] : asStringArray(rec.dns_names),
      notBefore: rec === undefined ? null : (asString(rec.not_before) ?? null),
      notAfter: rec === undefined ? null : (asString(rec.not_after) ?? null),
      revoked: rec === undefined ? null : (asBoolean(rec.revoked) ?? null),
      certSha256: rec === undefined ? null : (asString(rec.cert_sha256) ?? null),
      pubkeySha256: rec === undefined ? null : (asString(rec.pubkey_sha256) ?? null),
      issuer
    }
  ];
}
