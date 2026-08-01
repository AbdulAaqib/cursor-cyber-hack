import { NextResponse } from 'next/server';
import { detachAdminPolicy, reattachAdminPolicy } from '@/lib/aws-remediation';

export async function POST(request: Request) {
  if (process.env.USE_LIVE_AWS !== 'true') {
    return NextResponse.json(
      { ok: false, error: 'Remediation requires live AWS mode (USE_LIVE_AWS=true)' },
      { status: 400 },
    );
  }

  let body: { action?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json(
      { ok: false, error: 'Invalid JSON body' },
      { status: 400 },
    );
  }

  const { action } = body;

  if (action !== 'detach' && action !== 'reattach') {
    return NextResponse.json(
      { ok: false, error: 'action must be "detach" or "reattach"' },
      { status: 400 },
    );
  }

  try {
    const result =
      action === 'detach'
        ? await detachAdminPolicy()
        : await reattachAdminPolicy();
    return NextResponse.json({ ok: true, ...result });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      { ok: false, error: message },
      { status: 500 },
    );
  }
}
