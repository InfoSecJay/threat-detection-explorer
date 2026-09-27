// HTTP client for the public Detection Explorer API.
//
// Read-only, unauthenticated. The edge rate limit is 40 requests per 10 s
// per IP (429 + Retry-After), so a 429 is retried once after the stated
// wait and then surfaced; an agent loop that keeps hammering gets a clear
// error instead of a silent stall.

import { VERSION } from "./version.js";

export const DEFAULT_API_URL = "https://detectionexplorer.io/api/v1";
export const SITE_URL = "https://detectionexplorer.io";

export const USER_AGENT = `detection-explorer-mcp/${VERSION} (+https://github.com/InfoSecJay/threat-detection-explorer)`;

export type ParamValue = string | number | boolean | readonly string[] | undefined | null;
export type Params = Record<string, ParamValue>;

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "ApiError";
  }
}

export interface ClientOptions {
  baseUrl?: string;
  fetch?: FetchLike;
  timeoutMs?: number;
  /** Longest Retry-After the client will sit out before giving up. */
  maxRetryAfterMs?: number;
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** FastAPI error bodies: {"detail": "..."} or {"detail": [{loc, msg}, ...]}. */
function describeErrorBody(body: string): string {
  try {
    const parsed = JSON.parse(body) as { detail?: unknown };
    const detail = parsed.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((d: { loc?: unknown[]; msg?: string }) => {
          const where = Array.isArray(d.loc) ? d.loc.filter((p) => p !== "query" && p !== "path").join(".") : "";
          return where ? `${where}: ${d.msg ?? "invalid"}` : (d.msg ?? "invalid");
        })
        .join("; ");
    }
  } catch {
    // not JSON; fall through
  }
  return body.slice(0, 300).trim() || "no response body";
}

export class DetectionExplorerClient {
  readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;
  private readonly maxRetryAfterMs: number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(options: ClientOptions = {}) {
    this.baseUrl = (options.baseUrl || DEFAULT_API_URL).replace(/\/+$/, "");
    this.fetchImpl = options.fetch ?? ((url, init) => fetch(url, init));
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.maxRetryAfterMs = options.maxRetryAfterMs ?? 15_000;
    this.sleep = options.sleep ?? defaultSleep;
  }

  /** Build a URL; arrays become comma lists, empty values are dropped. */
  url(path: string, params: Params = {}): string {
    const search = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null || value === "") continue;
      if (Array.isArray(value)) {
        if (value.length === 0) continue;
        search.set(key, value.join(","));
      } else {
        search.set(key, String(value));
      }
    }
    const qs = search.toString();
    return `${this.baseUrl}${path}${qs ? `?${qs}` : ""}`;
  }

  async get<T = unknown>(path: string, params: Params = {}): Promise<T> {
    const url = this.url(path, params);
    for (let attempt = 0; ; attempt++) {
      const response = await this.fetchImpl(url, {
        headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      if (response.status === 429 && attempt === 0) {
        const retryAfter = Number(response.headers.get("retry-after"));
        const waitMs = Math.min(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 2000, this.maxRetryAfterMs);
        await this.sleep(waitMs);
        continue;
      }
      if (!response.ok) {
        const body = await response.text().catch(() => "");
        const hint =
          response.status === 429
            ? " (rate limited: the public API allows 40 requests per 10 seconds per IP; slow down and retry)"
            : "";
        throw new ApiError(`GET ${path} -> HTTP ${response.status}: ${describeErrorBody(body)}${hint}`, response.status);
      }
      return (await response.json()) as T;
    }
  }
}
