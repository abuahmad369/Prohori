import { toMarkdown, toSarif } from '@prohori/audit-engine';
import { isId } from '@/lib/ids';
import { getReport } from '@/lib/store';

export const runtime = 'nodejs';

function download(id: string, body: string, contentType: string, extension: string): Response {
  return new Response(body, {
    headers: { 'content-type': contentType, 'content-disposition': `attachment; filename="prohori-${id}.${extension}"` },
  });
}

/** Report downloads. Report ids are long and random; anyone with the link can read the report. */
export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const stored = isId(id) ? await getReport(id) : null;
  if (!stored) return Response.json({ error: 'Report not found.' }, { status: 404 });

  const format = new URL(request.url).searchParams.get('format') ?? 'json';
  switch (format) {
    case 'json':
      return download(id, JSON.stringify(stored.report, null, 2), 'application/json', 'json');
    case 'md':
      return download(id, toMarkdown(stored.report), 'text/markdown; charset=utf-8', 'md');
    case 'sarif':
      return download(id, JSON.stringify(toSarif(stored.report), null, 2), 'application/sarif+json', 'sarif');
    case 'sbom':
      return download(id, JSON.stringify(stored.sbom, null, 2), 'application/vnd.cyclonedx+json', 'cdx.json');
    default:
      return Response.json({ error: 'Unknown format. Use json, md, sarif or sbom.' }, { status: 400 });
  }
}
