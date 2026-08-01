import { NextResponse } from 'next/server';
import { openFixPr } from '@/lib/github-remediation';

export async function POST(request: Request) {
  let body: { findingId?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { ok: false, error: 'Invalid JSON body' },
      { status: 400 },
    );
  }

  const { findingId } = body;

  if (findingId !== 'SNYK-2026-001' && findingId !== 'SNYK-2026-002') {
    return NextResponse.json(
      { ok: false, error: 'findingId must be "SNYK-2026-001" or "SNYK-2026-002"' },
      { status: 400 },
    );
  }

  try {
    const result = await openFixPr(findingId);
    return NextResponse.json({ ok: true, prUrl: result.prUrl });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      { ok: false, error: message },
      { status: 500 },
    );
  }
}
