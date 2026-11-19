import Link from 'next/link';

const CHECKS = [
  { title: 'Secrets', text: 'API keys in code, secrets in NEXT_PUBLIC_ and VITE_ variables, committed .env files, AI keys used from the browser.' },
  { title: 'Access control', text: 'Supabase tables without row-level security, open Firebase rules, routes and server actions with no login check, unsigned payment webhooks.' },
  { title: 'AI endpoints', text: 'Routes that call OpenAI, Claude or Gemini with no login and no rate limit, so anyone can drain your AI budget.' },
  { title: 'Code safety', text: 'SQL and command injection, eval, raw HTML, disabled TLS checks, open CORS, weak password hashing, hard-coded JWT secrets.' },
  { title: 'Dependencies', text: 'Missing lockfiles, "latest" and "*" versions, git dependencies, and known vulnerabilities from OSV.dev. Exports a CycloneDX SBOM.' },
  { title: 'Production and upkeep', text: 'Debug mode, leaked stack traces, security headers, README, tests, CI, and a guide for the AI tools that will change the code next.' },
];

const PRODUCTS = [
  { name: 'Scan', status: 'Live', text: 'Free audit of any AI-built app: GitHub link, zip upload or the command-line tool.' },
  { name: 'Verified', status: 'Live', text: 'Apps with a score of at least 75 and no critical finding get a public report to show buyers and clients.' },
  { name: 'Market', status: 'Live (simulated payments)', text: 'Buy and sell verified apps only. bKash, Nagad and cards through SSLCommerz; international cards next.' },
  { name: 'Fix', status: 'Next', text: 'An AI agent opens a pull request that fixes the findings, priced per fixed issue.' },
  { name: 'Guard', status: 'Next', text: 'Runs inside Claude Code, Cursor and CI as a check before every deploy.' },
  { name: 'Comply', status: 'Later', text: 'SBOM history and vulnerability tracking for the EU Cyber Resilience Act.' },
];

export default function HomePage() {
  return (
    <>
      <div className="hero">
        <p className="eyebrow">The trust layer for AI-built software</p>
        <h1>Is your AI-built app safe to launch?</h1>
        <p className="lead">
          Prohori checks apps made with Lovable, Bolt, Cursor, Claude Code and similar tools for the mistakes behind 2026’s breaches. Apps
          that pass get a verified report, and can be sold in a marketplace that lists nothing else.
        </p>
        <div className="row" style={{ marginTop: 24 }}>
          <Link className="btn btn-primary" href="/scan">
            Scan an app for free
          </Link>
          <Link className="btn" href="/marketplace">
            Browse verified apps
          </Link>
        </div>
      </div>

      <section aria-labelledby="why">
        <h2 id="why">Why this matters now</h2>
        <div className="stats">
          <div className="card stat">
            <strong>44%</strong>
            <span className="muted small">
              of AI coding tasks introduced a security flaw in{' '}
              <a href="https://www.veracode.com/blog/2026-genai-code-security-report-ai-risk" rel="noreferrer" target="_blank">
                Veracode’s 2026 tests
              </a>
              .
            </span>
          </div>
          <div className="card stat">
            <strong>1.5 million</strong>
            <span className="muted small">
              API tokens exposed by one vibe-coded app within three days of launch, from a database with no row-level security (
              <a href="https://securitybrief.co.uk/story/moltbook-vibe-coded-flaw-exposed-ai-chats-keys" rel="noreferrer" target="_blank">
                Moltbook
              </a>
              ).
            </span>
          </div>
          <div className="card stat">
            <strong>11 Dec 2027</strong>
            <span className="muted small">
              The date software sold in the EU needs a machine-readable SBOM under the{' '}
              <a href="https://safedep.io/sbom-and-eu-cra-cyber-resilience-act" rel="noreferrer" target="_blank">
                Cyber Resilience Act
              </a>
              .
            </span>
          </div>
        </div>
      </section>

      <section aria-labelledby="checks">
        <h2 id="checks">What Prohori checks</h2>
        <p className="muted">39 rules in six areas, tuned to how AI-built apps actually break.</p>
        <div className="grid grid-3">
          {CHECKS.map((c) => (
            <div key={c.title} className="card">
              <h3>{c.title}</h3>
              <p className="muted small" style={{ marginBottom: 0 }}>
                {c.text}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section aria-labelledby="how">
        <h2 id="how">How it works</h2>
        <div className="grid grid-3">
          <div className="card">
            <p className="eyebrow">Step 1</p>
            <h3>Scan</h3>
            <p className="muted small" style={{ marginBottom: 0 }}>
              Paste a public GitHub link or upload a zip. The code is read in memory and never run or stored; only the findings are kept,
              with secrets masked.
            </p>
          </div>
          <div className="card">
            <p className="eyebrow">Step 2</p>
            <h3>Fix</h3>
            <p className="muted small" style={{ marginBottom: 0 }}>
              Every finding says where it is, why it matters and how to fix it. Download Markdown for your AI coding tool, SARIF for GitHub,
              or an SBOM.
            </p>
          </div>
          <div className="card">
            <p className="eyebrow">Step 3</p>
            <h3>Get verified and sell</h3>
            <p className="muted small" style={{ marginBottom: 0 }}>
              Score 75 or more with no critical finding and the app is verified. List it in the marketplace and get paid by bKash, Nagad or
              bank.
            </p>
          </div>
        </div>
      </section>

      <section aria-labelledby="products">
        <h2 id="products">The product line</h2>
        <div className="grid grid-3">
          {PRODUCTS.map((p) => (
            <div key={p.name} className="card">
              <div className="row spread">
                <h3 style={{ margin: 0 }}>{p.name}</h3>
                <span className={p.status.startsWith('Live') ? 'pill ok' : 'pill sev-info'}>{p.status}</span>
              </div>
              <p className="muted small" style={{ margin: '10px 0 0' }}>
                {p.text}
              </p>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
