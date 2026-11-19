import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="card" style={{ maxWidth: 560 }}>
      <h1>Not found</h1>
      <p className="muted">That page, report or listing does not exist.</p>
      <div className="row">
        <Link className="btn btn-primary" href="/scan">
          Scan an app
        </Link>
        <Link className="btn" href="/marketplace">
          Browse the marketplace
        </Link>
      </div>
    </div>
  );
}
