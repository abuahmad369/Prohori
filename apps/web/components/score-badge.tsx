export function scoreColor(score: number, verified: boolean): string {
  if (verified) return 'var(--ok)';
  return score >= 60 ? 'var(--medium)' : 'var(--high)';
}

export function ScoreBadge({ score, grade, verified, size = 116 }: { score: number; grade: string; verified: boolean; size?: number }) {
  const stroke = size * 0.09;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const filled = (Math.max(0, Math.min(100, score)) / 100) * circumference;
  const center = size / 2;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`Score ${score} out of 100, grade ${grade}`}>
      <circle cx={center} cy={center} r={radius} fill="none" stroke="var(--surface-2)" strokeWidth={stroke} />
      <circle
        cx={center}
        cy={center}
        r={radius}
        fill="none"
        stroke={scoreColor(score, verified)}
        strokeWidth={stroke}
        strokeLinecap="round"
        strokeDasharray={`${filled} ${circumference}`}
        transform={`rotate(-90 ${center} ${center})`}
      />
      <text x="50%" y="47%" textAnchor="middle" dominantBaseline="middle" fontSize={size * 0.29} fontWeight={800} fill="var(--ink)">
        {score}
      </text>
      <text x="50%" y="71%" textAnchor="middle" fontSize={size * 0.11} fill="var(--muted)">
        grade {grade}
      </text>
    </svg>
  );
}

export function VerifiedPill({ verified }: { verified: boolean }) {
  return verified ? (
    <span className="pill ok">
      <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
        <path d="m2.5 6.3 2.3 2.3 4.7-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      Verified
    </span>
  ) : (
    <span className="pill bad">Not verified</span>
  );
}
