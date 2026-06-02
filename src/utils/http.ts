export interface HttpResponse { status: number; headers: Record<string, string>; body: string; url: string; }

export async function fetchUrl(url: string, options: { timeout?: number; followRedirects?: boolean } = {}): Promise<HttpResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout ?? 10_000);
  try {
    const res = await fetch(url, { signal: controller.signal, redirect: options.followRedirects === false ? "manual" : "follow" });
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, headers, body: await res.text(), url: res.url };
  } finally { clearTimeout(timer); }
}

export function parseSetCookie(header: string): Array<Record<string, string>> {
  const cookies: Array<Record<string, string>> = [];
  for (const part of header.split(",")) {
    const attributes: Record<string, string> = {};
    for (const segment of part.split(";").map(s => s.trim())) {
      const eq = segment.indexOf("=");
      if (eq === -1) attributes[segment.toLowerCase()] = "true";
      else attributes[segment.slice(0, eq).trim().toLowerCase()] = segment.slice(eq + 1).trim();
    }
    cookies.push(attributes);
  }
  return cookies;
}
