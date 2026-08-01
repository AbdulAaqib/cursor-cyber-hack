import { openFixPr } from '@/lib/github-remediation';

export async function POST(request: Request) {
  let body: { findingId?: string };
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ ok: false, error: 'Invalid JSON body' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    );
  }

  const { findingId } = body;

  if (findingId !== 'SNYK-2026-001' && findingId !== 'SNYK-2026-002') {
    return new Response(
      JSON.stringify({ ok: false, error: 'findingId must be "SNYK-2026-001" or "SNYK-2026-002"' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    );
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const send = (obj: unknown) => {
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify(obj)}\n\n`),
        );
      };

      try {
        const result = await openFixPr(findingId, (line) =>
          send({ type: 'log', message: line }),
        );
        send({ type: 'done', ok: true, prUrl: result.prUrl, branchName: result.branchName });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        send({ type: 'done', ok: false, error: message });
      }

      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    },
  });
}
