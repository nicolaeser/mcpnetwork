export const TLS_VERSIONS = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"] as const;
export type TlsVersion = (typeof TLS_VERSIONS)[number];

export const DEFAULT_ALPN = ["h2", "http/1.1"] as const;

export interface TlsHandshakeOptions {
  readonly rejectUnauthorized: boolean;
  readonly requestOcsp: boolean;
  readonly servername?: string;
  readonly minVersion?: TlsVersion;
  readonly maxVersion?: TlsVersion;
  readonly alpn: readonly string[];
}

export function resolveTlsHandshakeOptions(
  input: {
    readonly rejectUnauthorized?: boolean;
    readonly requestOcsp?: boolean;
    readonly servername?: string;
    readonly minVersion?: TlsVersion;
    readonly maxVersion?: TlsVersion;
    readonly alpn?: readonly string[];
  },
  defaults: { readonly rejectUnauthorized: boolean }
): TlsHandshakeOptions {
  const servername = input.servername?.trim();
  return {
    rejectUnauthorized: input.rejectUnauthorized ?? defaults.rejectUnauthorized,
    requestOcsp: input.requestOcsp !== false,
    alpn: input.alpn === undefined ? [...DEFAULT_ALPN] : [...input.alpn],
    ...(servername !== undefined && servername.length > 0 ? { servername } : {}),
    ...(input.minVersion === undefined ? {} : { minVersion: input.minVersion }),
    ...(input.maxVersion === undefined ? {} : { maxVersion: input.maxVersion })
  };
}
