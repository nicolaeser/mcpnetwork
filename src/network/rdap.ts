import axios, { type AxiosInstance } from "axios";
import { isIP } from "node:net";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";
import { asRecord, asString, asStringArray, asUnknownArray } from "./shape.js";

export type RdapKind = "domain" | "ip";

export interface RdapEvent {
  readonly action: string;
  readonly date: string;
}

export interface RdapReport {
  readonly query: string;
  readonly kind: RdapKind;
  readonly path: string;
  readonly handle: string | null;
  readonly ldhName: string | null;
  readonly status: string[];
  readonly nameservers: string[];
  readonly registrar: string | null;
  readonly registrant: string | null;
  readonly registered: string | null;
  readonly expires: string | null;
  readonly updated: string | null;
  readonly events: RdapEvent[];
  readonly startAddress: string | null;
  readonly endAddress: string | null;
  readonly country: string | null;
}

export function createRdapClient(axiosInstance?: AxiosInstance): AxiosInstance {
  return (
    axiosInstance ??
    axios.create({
      baseURL: "https://rdap.org",
      timeout: 15_000,
      headers: {
        Accept: "application/rdap+json, application/json",
        "User-Agent": `${PACKAGE_NAME}/${PACKAGE_VERSION}`
      }
    })
  );
}

export async function rdapLookup(query: string, axiosInstance?: AxiosInstance): Promise<RdapReport> {
  const q = query.trim();
  const kind: RdapKind = isIP(q) === 0 ? "domain" : "ip";
  const path = kind === "ip" ? `/ip/${encodeURIComponent(q)}` : `/domain/${encodeURIComponent(q)}`;
  const client = createRdapClient(axiosInstance);
  const response = await client.get<unknown>(path);
  return parseRdap(q, kind, path, response.data);
}

export function parseRdap(query: string, kind: RdapKind, path: string, data: unknown): RdapReport {
  const rec = asRecord(data) ?? {};
  const nameservers = asUnknownArray(rec.nameservers).flatMap((item) => {
    const row = asRecord(item);
    const name = row === undefined ? undefined : asString(row.ldhName);
    return name === undefined ? [] : [name];
  });
  const events = asUnknownArray(rec.events).flatMap((item) => {
    const row = asRecord(item);
    if (row === undefined) return [];
    const action = asString(row.eventAction);
    const date = asString(row.eventDate);
    return action === undefined || date === undefined ? [] : [{ action, date }];
  });
  return {
    query,
    kind,
    path,
    handle: asString(rec.handle) ?? null,
    ldhName: asString(rec.ldhName) ?? null,
    status: asStringArray(rec.status),
    nameservers,
    registrar: entityFn(rec.entities, "registrar"),
    registrant: entityFn(rec.entities, "registrant"),
    registered: eventDate(events, "registration"),
    expires: eventDate(events, "expiration"),
    updated: eventDate(events, "last changed") ?? eventDate(events, "last update of rdap database"),
    events,
    startAddress: asString(rec.startAddress) ?? null,
    endAddress: asString(rec.endAddress) ?? null,
    country: asString(rec.country) ?? null
  };
}

function eventDate(events: readonly RdapEvent[], action: string): string | null {
  const needle = action.toLowerCase();
  for (const event of events) {
    if (event.action.toLowerCase() === needle) return event.date;
  }
  return null;
}

function entityFn(entities: unknown, role: string): string | null {
  for (const item of asUnknownArray(entities)) {
    const rec = asRecord(item);
    if (rec === undefined) continue;
    const roles = asStringArray(rec.roles);
    if (!roles.includes(role)) continue;
    const fn = vcardFn(rec.vcardArray);
    if (fn !== null) return fn;
  }
  return null;
}

function vcardFn(value: unknown): string | null {
  const rows = asUnknownArray(value);
  const body = rows.length === 2 ? asUnknownArray(rows[1]) : rows;
  for (const item of body) {
    const row = asUnknownArray(item);
    if (row[0] === "fn" && typeof row[3] === "string" && row[3].length > 0) return row[3];
  }
  return null;
}
