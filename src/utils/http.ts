export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  url: string;
}

export async function fetchUrl(
  url: string,
  options: { timeout?: number; followRedirects?: boolean } = {},
): Promise<HttpResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout ?? 10_000);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: options.followRedirects === false ? "manual" : "follow",
    });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    return { status: res.status, headers, body: await res.text(), url: res.url };
  } finally {
    clearTimeout(timer);
  }
}

export function parseSetCookie(header: string): Array<Record<string, string>> {
  if (!header) return [];
  const cookies: Array<Record<string, string>> = [];
  for (const part of header
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)) {
    const cookie: Record<string, string> = {};
    const segments = part.split(";").map((s) => s.trim());
    for (const segment of segments) {
      const eq = segment.indexOf("=");
      if (eq === -1) {
        cookie[segment.toLowerCase()] = "true";
      } else {
        const key = segment.slice(0, eq).trim().toLowerCase();
        const val = segment.slice(eq + 1).trim();
        cookie[key] = val;
      }
    }
    cookies.push(cookie);
  }
  return cookies;
}
