import { errorResponse, integer, readJson, text, UserError } from '@/lib/errors';
import { isId } from '@/lib/ids';
import { submitListing, type SubmitInput } from '@/lib/listings';
import { clientIp, rateLimit, tooManyRequests } from '@/lib/rate-limit';

export const runtime = 'nodejs';

// Phase 0 has no builder accounts, so anyone can submit. Accounts come first in Phase 1 (see progress.md).
export async function POST(request: Request) {
  const limit = rateLimit(`listing:${clientIp(request)}`, 5);
  if (!limit.ok) return tooManyRequests(limit.retryAfter);
  try {
    const body = await readJson(request);
    const input: SubmitInput = {
      title: text(body, 'title', { min: 3, max: 80 }),
      tagline: text(body, 'tagline', { min: 10, max: 140 }),
      description: text(body, 'description', { min: 40, max: 4000 }),
      category: text(body, 'category', { max: 40 }),
      priceBdt: integer(body, 'priceBdt', 500, 500_000),
      priceUsd: integer(body, 'priceUsd', 5, 5_000),
      builderName: text(body, 'builderName', { min: 2, max: 60 }),
    };
    if (body.source === 'scan') {
      const scanId = text(body, 'scanId', { max: 40 });
      if (!isId(scanId)) throw new UserError('That scan id is not valid.');
      input.scanId = scanId;
    } else if (body.source === 'github') {
      input.githubUrl = text(body, 'githubUrl', { max: 300 });
    } else if (body.source === 'demo') {
      input.demoSample = body.demoSample === 'vulnerable' ? 'vulnerable' : 'clean';
    } else {
      throw new UserError('Choose what to list: a verified scan, a GitHub repository or a demo project.');
    }

    const result = await submitListing(input);
    return Response.json(
      { published: result.published, slug: result.listing?.slug, scanId: result.scan.id, score: result.scan.score, reasons: result.reasons },
      { status: result.published ? 201 : 422 },
    );
  } catch (err) {
    return errorResponse(err, 'Submitting the app failed. Please try again.');
  }
}
