/** An error whose message is written for the user and safe to show. Anything else gets a generic reply. */
export class UserError extends Error {
  readonly status: number;
  readonly publicMessage: string;

  constructor(publicMessage: string, status = 400) {
    super(publicMessage);
    this.name = 'UserError';
    this.status = status;
    this.publicMessage = publicMessage;
  }
}

export function errorResponse(err: unknown, fallback = 'Something went wrong. Please try again.'): Response {
  if (err instanceof UserError) return Response.json({ error: err.publicMessage }, { status: err.status });
  console.error(err);
  return Response.json({ error: fallback }, { status: 500 });
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export async function readJson(request: Request): Promise<Record<string, unknown>> {
  const body = (await request.json().catch(() => null)) as unknown;
  if (!isRecord(body)) throw new UserError('Send a JSON object.');
  return body;
}

export function text(body: Record<string, unknown>, key: string, { min = 1, max = 200 }: { min?: number; max?: number } = {}): string {
  const raw = body[key];
  const value = typeof raw === 'string' ? raw.trim() : '';
  if (value.length < min || value.length > max) throw new UserError(`"${key}" must be ${min} to ${max} characters.`);
  return value;
}

export function integer(body: Record<string, unknown>, key: string, min: number, max: number): number {
  const raw = body[key];
  const value = typeof raw === 'number' ? raw : typeof raw === 'string' ? Number(raw) : Number.NaN;
  if (!Number.isInteger(value) || value < min || value > max) throw new UserError(`"${key}" must be a whole number from ${min} to ${max}.`);
  return value;
}
