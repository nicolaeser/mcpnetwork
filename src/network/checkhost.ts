import axios, { type AxiosInstance } from "axios";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";

export type CheckHostType = "ping" | "http" | "tcp" | "udp" | "dns";

export interface CheckHostStart {
  readonly ok: number;
  readonly request_id: string;
  readonly permanent_link?: string;
  readonly nodes?: Record<string, unknown>;
}

export function createCheckHostClient(axiosInstance?: AxiosInstance): AxiosInstance {
  return (
    axiosInstance ??
    axios.create({
      baseURL: "https://check-host.net",
      timeout: 20_000,
      headers: {
        Accept: "application/json",
        "User-Agent": `${PACKAGE_NAME}/${PACKAGE_VERSION}`
      }
    })
  );
}

export async function listCheckHostNodes(client: AxiosInstance): Promise<unknown> {
  const response = await client.get("/nodes/hosts");
  return response.data;
}

export async function startCheckHost(
  client: AxiosInstance,
  type: CheckHostType,
  host: string,
  options: { readonly maxNodes?: number; readonly nodes?: readonly string[] } = {}
): Promise<CheckHostStart> {
  const params = new URLSearchParams({ host });
  if (options.maxNodes !== undefined) params.set("max_nodes", String(options.maxNodes));
  if (options.nodes !== undefined) {
    for (const node of options.nodes) params.append("node", node);
  } else if (options.maxNodes === undefined) {
    params.set("max_nodes", "3");
  }
  const response = await client.get(`/check-${type}?${params.toString()}`);
  const data = response.data as CheckHostStart;
  if (data.ok !== 1 || typeof data.request_id !== "string") {
    throw new Error("Check-Host rejected the request.");
  }
  return data;
}

export async function fetchCheckHostResult(client: AxiosInstance, requestId: string): Promise<unknown> {
  const response = await client.get(`/check-result/${requestId}`);
  return response.data;
}

export async function waitCheckHostResult(
  client: AxiosInstance,
  requestId: string,
  timeoutMs = 20_000
): Promise<unknown> {
  const started = Date.now();
  let last: unknown = null;
  while (Date.now() - started < timeoutMs) {
    last = await fetchCheckHostResult(client, requestId);
    if (!isPending(last)) return last;
    await delay(1_500);
  }
  return last;
}

function isPending(value: unknown): boolean {
  if (value === null || typeof value !== "object") return true;
  const entries = Object.values(value as Record<string, unknown>);
  if (entries.length === 0) return true;
  return entries.some((item) => item === null);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
