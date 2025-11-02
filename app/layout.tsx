export const metadata = {
  title: "AI IDOR Scanner",
  description: "MVP Bug Bounty Hunting Framework for IDOR/Auth Bypass",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: 'Inter, system-ui, Arial', background: '#0b1220', color: '#e6edf3' }}>
        <div style={{ maxWidth: 1100, margin: '0 auto', padding: '24px' }}>
          <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
            <h1 style={{ fontSize: 22, margin: 0 }}>AI IDOR & Auth Bypass Scanner</h1>
            <a href="https://vercel.com" target="_blank" rel="noreferrer" style={{ color: '#8fb5ff', fontSize: 12 }}>Deployed on Vercel</a>
          </header>
          {children}
        </div>
      </body>
    </html>
  );
}
