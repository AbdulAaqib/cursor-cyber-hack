import {
  AWS_REMEDIATION_TARGETS,
  detachPolicy,
  reattachPolicy,
} from '@/lib/aws-remediation';

export async function POST(request: Request) {
  if (process.env.USE_LIVE_AWS !== 'true') {
    return new Response(
      JSON.stringify({ ok: false, error: 'Remediation requires live AWS mode (USE_LIVE_AWS=true)' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    );
  }

  let body: { action?: string; findingId?: string };
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ ok: false, error: 'Invalid JSON body' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    );
  }

  const { action, findingId } = body;

  if (action !== 'detach' && action !== 'reattach') {
    return new Response(
      JSON.stringify({ ok: false, error: 'action must be "detach" or "reattach"' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } },
    );
  }

  if (!findingId || !AWS_REMEDIATION_TARGETS[findingId]) {
    return new Response(
      JSON.stringify({ ok: false, error: `findingId must be one of ${Object.keys(AWS_REMEDIATION_TARGETS).join(', ')}` }),
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
        const result =
          action === 'detach'
            ? await detachPolicy(findingId, (line) => send({ type: 'log', message: line }))
            : await reattachPolicy(findingId, (line) => send({ type: 'log', message: line }));
        send({ type: 'done', ok: true, ...result });
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
