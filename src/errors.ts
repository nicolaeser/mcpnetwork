import { UpstreamHttpError } from "./upstream/client.js";

export class ConfirmationRequiredError extends Error {
  public constructor(toolName: string) {
    super(`${toolName} is a write. Pass confirm: true after reviewing the arguments.`);
    this.name = "ConfirmationRequiredError";
  }
}

export class MissingTokenError extends Error {
  public constructor() {
    super(
      "No session is configured. Use HTTP OAuth or run stdio."
    );
    this.name = "MissingTokenError";
  }
}

export function errorMessage(error: unknown): string {
  if (error instanceof UpstreamHttpError) return error.message;
  return error instanceof Error ? error.message : String(error);
}

export function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "Error";
}
