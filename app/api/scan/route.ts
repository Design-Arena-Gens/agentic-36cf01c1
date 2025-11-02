import { NextRequest } from "next/server";
import { z } from "zod";
import { distance as levenshteinDistance } from "fastest-levenshtein";
import { v4 as uuidv4 } from "uuid";

export const runtime = "nodejs";

const HeaderSchema = z.record(z.string()).optional();

const EndpointSchema = z.object({
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
  pathTemplate: z.string(),
  pathParams: z.array(z.object({ name: z.string(), samples: z.array(z.string()).min(1) })).default([]),
  queryParams: z.array(z.object({ name: z.string(), samples: z.array(z.string()).min(1) })).optional(),
  bodyTemplate: z.union([z.string(), z.record(z.any())]).optional()
});

const ScanRequestSchema = z.object({
  baseUrl: z.string().url(),
  endpoints: z.array(EndpointSchema).min(1),
  authContexts: z.object({
    victim: z.object({ headers: HeaderSchema, cookies: HeaderSchema }).partial(),
    attacker: z.object({ headers: HeaderSchema, cookies: HeaderSchema }).partial().optional(),
    unauthenticated: z.boolean().optional()
  }),
  speedGateThreshold: z.number().min(0).max(1).default(0.8),
  maxConcurrency: z.number().min(1).max(12).default(5),
  timeoutMs: z.number().min(1000).max(60000).default(8000)
});

function applyTemplate(input: string, vars: Record<string, string>): string {
  return input.replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? `{${k}}`);
}

function buildUrl(baseUrl: string, pathTmpl: string, qp: Record<string, string | undefined>): string {
  const url = new URL(baseUrl.replace(/\/$/, "") + "/" + pathTmpl.replace(/^\//, ""));
  for (const [k, v] of Object.entries(qp)) {
    if (v !== undefined) url.searchParams.set(k, v);
  }
  return url.toString();
}

function normalizeBodyText(value: unknown): string {
  try {
    if (typeof value === 'string') return value;
    if (value && typeof value === 'object') return JSON.stringify(value);
    return String(value ?? '');
  } catch {
    return '';
  }
}

function redactVolatile(text: string): string {
  return text
    .replace(/\b\d{13,}\b/g, "<num>")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, "<uuid>")
    .replace(/"(created|updated|timestamp|ts|date)"\s*:\s*"[^"]+"/gi, '"$1":"<ts>"');
}

function tokenSet(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .replace(/[^a-z0-9_\-]+/g, ' ')
      .split(/\s+/)
      .filter(Boolean)
  );
}

function jaccard(a: Set<string>, b: Set<string>): number {
  const inter = new Set([...a].filter(x => b.has(x)));
  const uni = new Set([...a, ...b]);
  return uni.size ? inter.size / uni.size : 0;
}

function similarity(aRaw: string, bRaw: string): number {
  const a = redactVolatile(aRaw);
  const b = redactVolatile(bRaw);
  const ta = tokenSet(a);
  const tb = tokenSet(b);
  const j = jaccard(ta, tb);
  const lev = 1 - Math.min(1, levenshteinDistance(a, b) / Math.max(a.length, b.length, 1));
  return (j * 0.6) + (lev * 0.4);
}

async function timedFetch(input: RequestInfo | URL, init: RequestInit, timeoutMs: number): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

type AuthCtxName = "victim" | "attacker" | "unauthenticated";

export async function POST(req: NextRequest) {
  const parsed = ScanRequestSchema.safeParse(await req.json());
  if (!parsed.success) {
    return new Response(JSON.stringify({ error: parsed.error.flatten() }), { status: 400 });
  }
  const cfg = parsed.data;

  const tasks: Array<() => Promise<any>> = [];
  const findings: any[] = [];

  function buildInit(headers?: Record<string, string>, cookies?: Record<string, string>): RequestInit {
    const h = new Headers(headers || {});
    if (cookies && Object.keys(cookies).length) {
      const cookieStr = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
      h.set('cookie', cookieStr);
    }
    return { headers: h };
  }

  for (const ep of cfg.endpoints) {
    const paramNameToSamples: Record<string, string[]> = Object.fromEntries(
      ep.pathParams.map(p => [p.name, p.samples])
    );
    const primaryParam = ep.pathParams[0];
    if (!primaryParam) continue;

    const victimId = primaryParam.samples[0];
    const attackerId = (primaryParam.samples[1] ?? primaryParam.samples[0]);

    const pathVictim = applyTemplate(ep.pathTemplate, { [primaryParam.name]: victimId });
    const urlVictim = buildUrl(cfg.baseUrl, pathVictim, {});

    const victimInit = buildInit(cfg.authContexts.victim.headers, cfg.authContexts.victim.cookies);

    tasks.push(async () => {
      let baselineText = "";
      let baselineStatus = 0;
      try {
        const resVictim = await timedFetch(urlVictim, { method: ep.method, ...victimInit }, cfg.timeoutMs);
        baselineStatus = resVictim.status;
        baselineText = await resVictim.text();
      } catch (e) {
        // baseline failed; skip this endpoint
        return;
      }

      // Attacker tries to access victim's resource
      const pathAttackVictim = pathVictim; // same path, victim id in URL
      const urlAttackVictim = buildUrl(cfg.baseUrl, pathAttackVictim, {});
      const attackerInit = cfg.authContexts.attacker ? buildInit(cfg.authContexts.attacker.headers, cfg.authContexts.attacker.cookies) : {};

      let attackerStatus = 0;
      let attackerText = "";
      try {
        const resAtk = await timedFetch(urlAttackVictim, { method: ep.method, ...attackerInit }, cfg.timeoutMs);
        attackerStatus = resAtk.status;
        attackerText = await resAtk.text();
      } catch (e) {
        // ignore
      }

      const evid: string[] = [];
      let score = 0;

      if (baselineStatus >= 200 && baselineStatus < 300) {
        const sim = similarity(baselineText, attackerText);
        // Base scoring
        if (attackerStatus >= 200 && attackerStatus < 300) {
          score += 0.6; // unauthorized success
          score += Math.min(0.4, sim * 0.4); // content similarity
          evid.push(`Similarity victim?attacker: ${(sim * 100).toFixed(1)}%`);
        } else if (attackerStatus === 401 || attackerStatus === 403) {
          score += 0.05; // looks protected
        }

        // Evidence from ID consistency
        try {
          const maybeJsonVictim = JSON.parse(baselineText);
          const maybeJsonAtk = JSON.parse(attackerText);
          const vIdStr = JSON.stringify(maybeJsonVictim).match(/"id"\s*:\s*"?(\w+)"?/i)?.[1];
          const aIdStr = JSON.stringify(maybeJsonAtk).match(/"id"\s*:\s*"?(\w+)"?/i)?.[1];
          if (vIdStr && aIdStr && vIdStr === attackerId) {
            // attacker sees own id when requesting victim resource -> likely not IDOR
            score -= 0.1;
          }
          if (vIdStr && JSON.stringify(maybeJsonAtk).includes(vIdStr)) {
            score += 0.15;
            evid.push(`Victim id '${vIdStr}' present in attacker response`);
          }
        } catch {}
      }

      score = Math.max(0, Math.min(1, score));

      if (score >= cfg.speedGateThreshold) {
        findings.push({
          id: uuidv4(),
          endpoint: pathVictim,
          method: ep.method,
          attackVector: "Attacker requests victim's resource via URL id",
          statusVictim: baselineStatus,
          statusAttacker: attackerStatus,
          confidence: Number(score.toFixed(3)),
          evidence: evid
        });
      }

      // Optional: unauthenticated attempt
      if (cfg.authContexts.unauthenticated) {
        try {
          const resUnauth = await timedFetch(urlVictim, { method: ep.method }, cfg.timeoutMs);
          const textUnauth = await resUnauth.text();
          if (resUnauth.status >= 200 && resUnauth.status < 300) {
            const sim = similarity(baselineText, textUnauth);
            let s = 0.65 + Math.min(0.35, sim * 0.35);
            const ev: string[] = [`Similarity victim?unauth: ${(sim * 100).toFixed(1)}%`];
            if (s >= cfg.speedGateThreshold) {
              findings.push({
                id: uuidv4(),
                endpoint: pathVictim,
                method: ep.method,
                attackVector: "Unauthenticated requests victim's resource",
                statusVictim: baselineStatus,
                statusAttacker: resUnauth.status,
                confidence: Number(s.toFixed(3)),
                evidence: ev
              });
            }
          }
        } catch {}
      }
    });
  }

  async function runWithConcurrency<T>(jobs: Array<() => Promise<T>>, max: number): Promise<T[]> {
    const out: T[] = [];
    let idx = 0;
    const runners = new Array(Math.min(max, jobs.length)).fill(0).map(async () => {
      while (idx < jobs.length) {
        const current = idx++;
        try {
          const res = await jobs[current]!();
          // @ts-ignore
          out.push(res);
        } catch {}
      }
    });
    await Promise.all(runners);
    return out;
  }

  await runWithConcurrency(tasks, cfg.maxConcurrency);

  return new Response(JSON.stringify({ findings }), { headers: { 'content-type': 'application/json' } });
}
