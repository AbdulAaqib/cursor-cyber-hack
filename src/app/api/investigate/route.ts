import { model } from '@/lib/ai';
import { getResourceSensitivity, getTrustEdges, getAttachedPolicyDetails } from '@/lib/graph';
import { listFiles, readFile } from '@/lib/repo-explorer';
import findings from '@/data/findings.json';
import { isStepCount, streamText, generateObject } from 'ai';
import { z } from 'zod';

export async function POST(request: Request) {
  const { findingId } = (await request.json()) as { findingId?: string };
  const finding = (findings as Array<{
    id: string;
    package: string;
    cve: string;
    cvss: number;
    affectedNode: string;
    repoPath: string;
    description: string;
  }>).find((f) => f.id === findingId);

  if (!finding) {
    return new Response(JSON.stringify({ error: 'Finding not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const send = (obj: unknown) => {
        controller.enqueue(
          encoder.encode(`data: ${JSON.stringify(obj)}\n\n`),
        );
      };

      // ───────────────────────────────────────────────
      // Phase 1: Code exploration (raw file reading)
      // ───────────────────────────────────────────────
      const codeResult = streamText({
        model,
        stopWhen: isStepCount(4),
        system: `You are a code-reachability analyst. Your job is to determine whether the vulnerable function described in a finding is actually invoked in the active code path.

You have two tools:
- listFiles(dir): lists files in a directory relative to the demo-repo root.
- readFile(path): reads the contents of a file relative to the demo-repo root.

Rules:
1. Call listFiles on the finding's repoPath to see what files are there.
2. Read the relevant file(s) with readFile — likely more than one, since you need to follow the import/call chain. Read the entry-point file, notice what it imports and calls, then read that file too. Open every file you need to fully trace whether the vulnerable function is actually invoked. Do not stop after one file.
3. Explicitly state in plain English, citing what you actually read, whether the vulnerable function is reachable/invoked or dead code.

Be concise but thorough.`,
        prompt: `Investigate code reachability for this finding:
- ID: ${finding.id}
- Package: ${finding.package}
- CVE: ${finding.cve}
- CVSS: ${finding.cvss}
- Affected node: ${finding.affectedNode}
- Repo path: ${finding.repoPath}
- Description: ${finding.description}

Begin by listing the files in the repo path "${finding.repoPath}".`,
        tools: {
          listFiles: {
            description:
              'List files in a directory relative to the demo-repo root.',
            inputSchema: z.object({ dir: z.string() }),
            execute: async ({ dir }: { dir: string }) => listFiles(dir),
          },
          readFile: {
            description:
              'Read the contents of a file relative to the demo-repo root.',
            inputSchema: z.object({ path: z.string() }),
            execute: async ({ path }: { path: string }) => readFile(path),
          },
        },
      });

      const codeToolCalls: Array<{
        toolCallId: string;
        toolName: string;
        input: unknown;
        output?: unknown;
      }> = [];
      const codeReasoningParts: string[] = [];

      for await (const part of codeResult.fullStream) {
        send(part);

        if (part.type === 'text-delta') {
          codeReasoningParts.push(part.text);
        }
        if (part.type === 'tool-call') {
          codeToolCalls.push({
            toolCallId: part.toolCallId,
            toolName: part.toolName,
            input: part.input,
          });
        }
        if (part.type === 'tool-result') {
          const tc = codeToolCalls.find((t) => t.toolCallId === part.toolCallId);
          if (tc) tc.output = part.output;
        }
      }

      const codeTraceText = `Code-reachability investigation:
${codeReasoningParts.join('')}

Code tool calls:
${codeToolCalls.map((tc) => `- ${tc.toolName}(${JSON.stringify(tc.input)}) => ${JSON.stringify(tc.output)}`).join('\n')}`;

      // ───────────────────────────────────────────────
      // Phase 2: IAM trust-graph tracing
      // ───────────────────────────────────────────────
      const iamResult = streamText({
        model,
        stopWhen: isStepCount(8),
        system: `You are an IAM blast-radius tracer. Your job is to investigate how far an attacker could move from the affected IAM node through trust edges.

You have three tools available:
- getTrustEdges(node): returns outgoing trust edges (AssumeRole, PassRole, AttachRolePolicy) from a node.
- getAttachedPolicyDetails(node): returns the actual attached IAM policies for a role, with their raw actions and resources arrays. This is your PRIMARY signal for judging how dangerous a role is — read the actual actions and resources and reason about them in your own words.
- getResourceSensitivity(node): returns a pre-baked sensitivity tag (LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN) and reason. Use this ONLY as a secondary cross-check, not as your primary judgment.

Rules:
1. Start from the affectedNode. Call getTrustEdges on it.
2. For every new node discovered, call BOTH getAttachedPolicyDetails (primary signal) AND getResourceSensitivity (secondary cross-check) before deciding whether to keep expanding.
3. CRITICAL: checking a node's sensitivity is NOT the same as knowing where the trail ends. For every new node getTrustEdges returns (not just the starting node), you MUST also call getTrustEdges on THAT node before deciding to stop — a MEDIUM-sensitivity node can still be a stepping stone to something CRITICAL one hop further. Only stop expanding a specific path once getTrustEdges on the current node returns an empty array (a true dead end), or you hit a CRITICAL/ADMIN node, or you've gone 4 hops deep on that path.
4. Explicitly reason in plain English about whether the path is genuinely dangerous or a benign dead end.
5. Decide yourself when to stop expanding overall. Do not hardcode a shallower traversal depth than rule 3 requires.
6. After finishing the trace, explicitly check whether any visited node had a pendingChange field in its sensitivity metadata. State what additional risk that pending change would introduce if merged. If no pendingChange was found on any visited node, state that explicitly.

Be concise but thorough in your reasoning.`,
        prompt: `The code-reachability investigation has already been completed. Here is its conclusion:

${codeTraceText}

Now trace the IAM blast radius starting from the affected node: ${finding.affectedNode}.

Investigate this finding:
- ID: ${finding.id}
- Package: ${finding.package}
- CVE: ${finding.cve}
- CVSS: ${finding.cvss}
- Affected node: ${finding.affectedNode}
- Description: ${finding.description}

Begin by calling getTrustEdges on "${finding.affectedNode}".`,
        tools: {
          getTrustEdges: {
            description:
              'Get outgoing trust edges (AssumeRole, PassRole, AttachRolePolicy) for a given IAM node.',
            inputSchema: z.object({ node: z.string() }),
            execute: async ({ node }: { node: string }) => getTrustEdges(node),
          },
          getAttachedPolicyDetails: {
            description:
              'Get the actual attached IAM policies for a role, with raw actions and resources arrays.',
            inputSchema: z.object({ node: z.string() }),
            execute: async ({ node }: { node: string }) => getAttachedPolicyDetails(node),
          },
          getResourceSensitivity: {
            description:
              'Get pre-baked sensitivity metadata (LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN) and reason for a given IAM node. Use only as a secondary cross-check.',
            inputSchema: z.object({ node: z.string() }),
            execute: async ({ node }: { node: string }) => getResourceSensitivity(node),
          },
        },
      });

      const iamToolCalls: Array<{
        toolCallId: string;
        toolName: string;
        input: unknown;
        output?: unknown;
      }> = [];
      const iamReasoningParts: string[] = [];

      for await (const part of iamResult.fullStream) {
        send(part);

        if (part.type === 'text-delta') {
          iamReasoningParts.push(part.text);
        }
        if (part.type === 'tool-call') {
          iamToolCalls.push({
            toolCallId: part.toolCallId,
            toolName: part.toolName,
            input: part.input,
          });
        }
        if (part.type === 'tool-result') {
          const tc = iamToolCalls.find((t) => t.toolCallId === part.toolCallId);
          if (tc) tc.output = part.output;
        }
      }

      // ───────────────────────────────────────────────
      // Verdict
      // ───────────────────────────────────────────────
      const traceText = `Finding: ${finding.id} (${finding.package}, ${finding.cve}, CVSS ${finding.cvss})
Affected node: ${finding.affectedNode}
Repo path: ${finding.repoPath}
Description: ${finding.description}

${codeTraceText}

IAM tracing reasoning:
${iamReasoningParts.join('')}

IAM tool calls and results:
${iamToolCalls.map((tc) => `- ${tc.toolName}(${JSON.stringify(tc.input)}) => ${JSON.stringify(tc.output)}`).join('\n')}`;

      const verdict = await generateObject({
        model,
        schema: z.object({
          severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
          pathSummary: z.string(),
          hops: z.array(
            z.object({
              from: z.string(),
              to: z.string(),
              event: z.string(),
              risky: z.boolean(),
              reason: z.string(),
            }),
          ),
          counterfactual: z.string(),
          recommendation: z.string(),
          codeReachable: z.boolean(),
          codeReachabilityReason: z.string(),
        }),
        prompt: `Based on the following investigation trace, produce a structured severity verdict.

${traceText}

Instructions:
- severity: choose CRITICAL, HIGH, MEDIUM, or LOW based on actual reachability to sensitive roles/policies AND whether the vulnerable code is actually invoked, not just the CVSS score.
- pathSummary: a one-sentence summary of the attack path discovered.
- hops: the concrete hops traced (from -> to via event), with a boolean risky flag and short reason.
- counterfactual: describe any pendingChange found on visited nodes and the additional risk it would introduce. If none, say so explicitly.
- recommendation: a one-sentence remediation recommendation.
- codeReachable: true if the vulnerable function is actually invoked in the active code path, false if it is dead/unreachable code.
- codeReachabilityReason: a short sentence explaining why the code is or isn't reachable, referencing the files the agent read and what they showed.`,
      });

      send({ type: 'verdict', data: verdict.object });
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
