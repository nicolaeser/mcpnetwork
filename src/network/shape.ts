export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

export function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function asFiniteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export function asBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

export function asUnknownArray(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

export function asStringArray(value: unknown): string[] {
  return asUnknownArray(value).flatMap((item) => (typeof item === "string" ? [item] : []));
}

export function errnoCode(error: unknown): string {
  const rec = asRecord(error);
  return rec !== undefined && typeof rec.code === "string" ? rec.code : "ERROR";
}

export function errnoMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
