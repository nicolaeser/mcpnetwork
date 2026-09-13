import axios, { isAxiosError, type AxiosInstance, type AxiosResponse } from "axios";
import { Agent as HttpsAgent } from "node:https";
import { PACKAGE_NAME, PACKAGE_VERSION } from "../version.js";

const MAX_BODY = 65_536;

export interface HttpHop {
  readonly url: string;
  readonly status: number;
  readonly statusText: string;
  readonly ms: number;
  readonly location: string | null;
  readonly contentType: string | null;
  readonly server: string | null;
  readonly hsts: string | null;
}

export interface HttpProbeReport {
  readonly ok: boolean;
  readonly finalUrl: string;
  readonly hops: HttpHop[];
  readonly rejectUnauthorized: boolean;
  readonly followRedirects: boolean;
  readonly message?: string;
}

export function createProbeClient(axiosInstance?: AxiosInstance): AxiosInstance {
  return (
    axiosInstance ??
    axios.create({
      timeout: 10_000,
      maxRedirects: 0,
      maxContentLength: MAX_BODY,
      maxBodyLength: MAX_BODY,
      validateStatus: () => true,
      headers: { "User-Agent": `${PACKAGE_NAME}/${PACKAGE_VERSION}` }
    })
  );
}

export function assertHttpUrl(url: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("URL must include http:// or https://");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("URL must be http or https");
  }
  return parsed;
}

export function stripUserinfo(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.username = "";
    parsed.password = "";
    return parsed.toString();
  } catch {
    return url;
  }
}

export async function probeHttp(input: {
  readonly url: string;
  readonly method?: string;
  readonly followRedirects?: boolean;
  readonly maxRedirects?: number;
  readonly timeoutMs?: number;
  readonly rejectUnauthorized?: boolean;
  readonly axiosInstance?: AxiosInstance;
}): Promise<HttpProbeReport> {
  const timeoutMs = input.timeoutMs ?? 10_000;
  const follow = input.followRedirects !== false;
  const rejectUnauthorized = input.rejectUnauthorized !== false;
  const maxRedirects = Math.min(Math.max(input.maxRedirects ?? 6, 0), 10);
  const hopLimit = follow ? Math.max(maxRedirects, 1) : 1;
  const client = createProbeClient(input.axiosInstance);
  const hops: HttpHop[] = [];
  let url = assertHttpUrl(input.url).toString();
  for (let i = 0; i < hopLimit; i++) {
    assertHttpUrl(url);
    const started = Date.now();
    const response = await hop(client, url, input.method ?? "GET", timeoutMs, rejectUnauthorized);
    const headers = headerMap(response.headers);
    const location = header(headers, "location");
    hops.push({
      url: stripUserinfo(url),
      status: response.status,
      statusText: response.statusText,
      ms: Date.now() - started,
      location,
      contentType: header(headers, "content-type"),
      server: header(headers, "server"),
      hsts: header(headers, "strict-transport-security")
    });
    if (!follow || location === null || response.status < 300 || response.status >= 400) {
      return {
        ok: response.status >= 200 && response.status < 400,
        finalUrl: stripUserinfo(url),
        hops,
        rejectUnauthorized,
        followRedirects: follow
      };
    }
    url = new URL(location, url).toString();
  }
  return {
    ok: false,
    finalUrl: stripUserinfo(url),
    hops,
    rejectUnauthorized,
    followRedirects: follow,
    message: "Too many redirects."
  };
}

async function hop(
  client: AxiosInstance,
  url: string,
  method: string,
  timeoutMs: number,
  rejectUnauthorized: boolean
): Promise<AxiosResponse> {
  try {
    return await client.request({
      url,
      method,
      timeout: timeoutMs,
      maxRedirects: 0,
      ...(rejectUnauthorized ? {} : { httpsAgent: new HttpsAgent({ rejectUnauthorized: false }) })
    });
  } catch (error) {
    if (isAxiosError(error) && error.response !== undefined) return error.response;
    throw error;
  }
}

function headerMap(headers: AxiosResponse["headers"]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (value === undefined || value === null || typeof value === "object") continue;
    out[key.toLowerCase()] = String(value);
  }
  return out;
}

function header(headers: Record<string, string>, name: string): string | null {
  return headers[name] ?? null;
}
