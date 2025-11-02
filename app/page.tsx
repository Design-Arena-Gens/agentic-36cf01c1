"use client";

import { useMemo, useState } from "react";

type ScanResult = {
  id: string;
  endpoint: string;
  method: string;
  attackVector: string;
  statusVictim: number;
  statusAttacker?: number;
  confidence: number;
  evidence: string[];
};

export default function Page() {
  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const defaultBaseUrl = origin + "/api/mock";

  const [baseUrl, setBaseUrl] = useState<string>(defaultBaseUrl);
  const [victimId, setVictimId] = useState<string>("1001");
  const [attackerId, setAttackerId] = useState<string>("1002");
  const [victimHeader, setVictimHeader] = useState<string>("x-user-id:1001");
  const [attackerHeader, setAttackerHeader] = useState<string>("x-user-id:1002");
  const [threshold, setThreshold] = useState<number>(0.8);
  const [loading, setLoading] = useState<boolean>(false);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  const headersFromText = (text: string): Record<string, string> => {
    const map: Record<string, string> = {};
    text
      .split(/\n|,/)
      .map((l) => l.trim())
      .filter(Boolean)
      .forEach((line) => {
        const idx = line.indexOf(":");
        if (idx > 0) {
          const k = line.slice(0, idx).trim();
          const v = line.slice(idx + 1).trim();
          if (k) map[k] = v;
        }
      });
    return map;
  };

  const onRun = async () => {
    setLoading(true);
    setError(null);
    setResults([]);
    try {
      const body = {
        baseUrl,
        endpoints: [
          {
            method: "GET",
            pathTemplate: "/users/{id}",
            pathParams: [
              { name: "id", samples: [victimId, attackerId] }
            ]
          }
        ],
        authContexts: {
          victim: { headers: headersFromText(victimHeader) },
          attacker: { headers: headersFromText(attackerHeader) },
          unauthenticated: true
        },
        speedGateThreshold: threshold,
        maxConcurrency: 4,
        timeoutMs: 8000
      };
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`Scan failed: ${res.status}`);
      const data = await res.json();
      setResults(data.findings || []);
    } catch (e: any) {
      setError(e?.message || "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  const riskColor = (c: number) => (c >= 0.9 ? '#ff7189' : c >= 0.8 ? '#ffb86b' : '#c0e28c');

  const demoNote = useMemo(() => (
    <p style={{ color: '#8aa2c0', fontSize: 13, lineHeight: 1.4 }}>
      Tip: The demo target <code>/api/mock/users/{"{id}"}</code> is intentionally vulnerable to IDOR.
      Use headers <code>x-user-id:1001</code> and <code>x-user-id:1002</code> to simulate different users.
    </p>
  ), []);

  return (
    <main>
      <section style={{ background: '#0f172a', border: '1px solid #1f2937', borderRadius: 12, padding: 16, marginBottom: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <label style={{ fontSize: 12, color: '#9fb5d1' }}>Base URL</label>
            <input style={s.input} value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://target.tld/api" />
          </div>
          <div>
            <label style={{ fontSize: 12, color: '#9fb5d1' }}>Speed Gate Threshold</label>
            <input style={s.input} type="number" min={0} max={1} step={0.05} value={threshold} onChange={(e) => setThreshold(parseFloat(e.target.value))} />
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
          <div>
            <label style={{ fontSize: 12, color: '#9fb5d1' }}>Victim ID</label>
            <input style={s.input} value={victimId} onChange={(e) => setVictimId(e.target.value)} />
          </div>
          <div>
            <label style={{ fontSize: 12, color: '#9fb5d1' }}>Attacker ID</label>
            <input style={s.input} value={attackerId} onChange={(e) => setAttackerId(e.target.value)} />
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
          <div>
            <label style={{ fontSize: 12, color: '#9fb5d1' }}>Victim Headers (k:v, one per line)</label>
            <textarea style={s.textarea} rows={4} value={victimHeader} onChange={(e) => setVictimHeader(e.target.value)} />
          </div>
          <div>
            <label style={{ fontSize: 12, color: '#9fb5d1' }}>Attacker Headers (k:v, one per line)</label>
            <textarea style={s.textarea} rows={4} value={attackerHeader} onChange={(e) => setAttackerHeader(e.target.value)} />
          </div>
        </div>
        <div style={{ marginTop: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
          <button onClick={onRun} disabled={loading} style={s.button}>{loading ? 'Scanning?' : 'Run Scan'}</button>
          {demoNote}
        </div>
      </section>

      <section style={{ background: '#0f172a', border: '1px solid #1f2937', borderRadius: 12, padding: 16 }}>
        <h3 style={{ marginTop: 0, fontSize: 16 }}>Findings</h3>
        {error && <div style={{ color: '#ff7189', marginBottom: 8 }}>{error}</div>}
        {results.length === 0 && !loading && <div style={{ color: '#8aa2c0' }}>No findings yet. Run a scan.</div>}
        {results.length > 0 && (
          <div style={{ display: 'grid', gap: 8 }}>
            {results.map((r) => (
              <div key={r.id} style={{ border: '1px solid #1f2937', borderRadius: 10, padding: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontWeight: 600 }}>
                    {r.method} {r.endpoint}
                  </div>
                  <div style={{ background: riskColor(r.confidence), color: '#0b1220', fontWeight: 700, padding: '2px 8px', borderRadius: 16, fontSize: 12 }}>
                    {(r.confidence * 100).toFixed(0)}%
                  </div>
                </div>
                <div style={{ color: '#9fb5d1', fontSize: 13, marginTop: 6 }}>
                  Attack Vector: {r.attackVector} | Victim {r.statusVictim} ? Attacker {r.statusAttacker}
                </div>
                {r.evidence?.length ? (
                  <ul style={{ marginTop: 8 }}>
                    {r.evidence.map((e, i) => (
                      <li key={i} style={{ color: '#c7d7ea', fontSize: 13 }}>{e}</li>
                    ))}
                  </ul>
                ) : null}
              </div>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}

const s: Record<string, React.CSSProperties> = {
  input: {
    width: '100%',
    background: '#0b1220',
    color: '#e6edf3',
    border: '1px solid #1f2937',
    borderRadius: 8,
    padding: '10px 12px',
    outline: 'none'
  },
  textarea: {
    width: '100%',
    background: '#0b1220',
    color: '#e6edf3',
    border: '1px solid #1f2937',
    borderRadius: 8,
    padding: '10px 12px',
    outline: 'none',
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace'
  },
  button: {
    background: '#8fb5ff',
    color: '#0b1220',
    border: 'none',
    borderRadius: 8,
    padding: '10px 14px',
    cursor: 'pointer',
    fontWeight: 700
  }
};
