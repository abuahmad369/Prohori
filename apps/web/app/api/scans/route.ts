import { DEMO_SAMPLES, type DemoSample } from '@/lib/constants';
import { demoProject } from '@/lib/demo-projects';
import { errorResponse, isRecord, UserError } from '@/lib/errors';
import { downloadGithubZip, parseGithubRepo } from '@/lib/github';
import { clientIp, rateLimit, tooManyRequests } from '@/lib/rate-limit';
import { osvEnabled, runAndStoreScan } from '@/lib/scan-service';
import type { ScanRecord } from '@/lib/store';
import { unzipProject } from '@/lib/unzip';

export const runtime = 'nodejs';

const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;

async function startScan(request: Request): Promise<ScanRecord> {
  const type = request.headers.get('content-type') ?? '';
  if (type.includes('multipart/form-data')) {
    // Refuse oversized uploads before reading the body. Uploads without a length are still read in
    // full, so production also needs a body-size limit at the proxy (see progress.md).
    const declared = Number(request.headers.get('content-length') ?? 0);
    if (declared > MAX_UPLOAD_BYTES + 64 * 1024) throw new UserError('The zip is over 25 MB. Use the command-line tool for large projects.', 413);
    const form = await request.formData();
    const file = form.get('file');
    if (!(file instanceof File)) throw new UserError('Choose a .zip file to upload.');
    if (!file.name.toLowerCase().endsWith('.zip')) throw new UserError('Upload the project as a .zip file.');
    if (file.size > MAX_UPLOAD_BYTES) throw new UserError('The zip is over 25 MB. Use the command-line tool for large projects.', 413);
    const entries = unzipProject(new Uint8Array(await file.arrayBuffer()));
    const name = file.name.replace(/\.zip$/i, '').slice(0, 80) || 'upload';
    return runAndStoreScan({ source: 'upload', label: file.name.slice(0, 120), projectName: name, entries, online: osvEnabled() });
  }

  const body = (await request.json().catch(() => null)) as unknown;
  if (!isRecord(body)) throw new UserError('Send a GitHub link, a zip file or a demo choice.');
  if (body.source === 'demo') {
    const sample: DemoSample = typeof body.sample === 'string' && Object.hasOwn(DEMO_SAMPLES, body.sample) ? (body.sample as DemoSample) : 'vulnerable';
    const demo = demoProject(sample);
    return runAndStoreScan({ source: 'demo', label: `Demo: ${demo.name}`, projectName: demo.name, entries: Object.entries(demo.files) });
  }
  if (body.source === 'github') {
    const repo = parseGithubRepo(typeof body.url === 'string' ? body.url : '');
    if (!repo) throw new UserError('Enter a public GitHub repository, like github.com/owner/repo.');
    const entries = unzipProject(await downloadGithubZip(repo.owner, repo.repo));
    return runAndStoreScan({ source: 'github', label: `${repo.owner}/${repo.repo}`, projectName: repo.repo, entries, online: osvEnabled() });
  }
  throw new UserError('Send a GitHub link, a zip file or a demo choice.');
}

// prohori-ignore access/route-without-auth: the free scanner is public by design; it is rate limited per IP and keeps only the report (with short masked snippets), never the uploaded files
export async function POST(request: Request) {
  const limit = rateLimit(`scan:${clientIp(request)}`, 10);
  if (!limit.ok) return tooManyRequests(limit.retryAfter);
  try {
    const record = await startScan(request);
    return Response.json({ id: record.id, score: record.score, grade: record.grade, verified: record.verified }, { status: 201 });
  } catch (err) {
    return errorResponse(err, 'The scan failed. Please try again.');
  }
}
