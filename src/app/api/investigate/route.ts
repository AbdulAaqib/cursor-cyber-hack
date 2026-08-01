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
        system: `You are a code-reachability analyst. Your job is to determine (1) whether the vulnerable function described in a finding is actually invoked in the active code path, and (2) what KIND of compromise this specific vulnerability grants an attacker if it IS reachable — because that determines everything about what happens downstream.

You have two tools:
- listFiles(dir): lists files in a directory relative to the demo-repo root.
- readFile(path): reads the contents of a file relative to the demo-repo root.

Rules:
1. Call listFiles on the finding's repoPath to see what files are there.
2. Read the relevant file(s) with readFile — likely more than one, since you need to follow the import/call chain. Read the entry-point file, notice what it imports and calls, then read that file too. Open every file you need to fully trace whether the vulnerable function is actually invoked. Do not stop after one file.
3. Explicitly state in plain English, citing what you actually read, whether the vulnerable function is reachable/invoked or dead code.
4. CRITICAL — classify the vulnerability's CAPABILITY based on its CVE/description, and state this explicitly: does this vulnerability grant the attacker arbitrary CODE EXECUTION (meaning they can act as the compromised service and use its IAM credentials to make AWS API calls)? Or is it a DENIAL OF SERVICE (the service crashes/hangs — the attacker gains NO code execution and NO ability to use the service's credentials)? Or is it INFORMATION DISCLOSURE (the attacker can read data the code already has access to, but cannot make new AWS API calls as the role)? This classification is not cosmetic — a DoS or read-only info-disclosure bug does NOT let an attacker pivot through IAM permissions, even if the code path is reachable and the role has dangerous permissions, because the attacker never gains the ability to act as that role in the first place. Say this explicitly if it applies.

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
        system: `You are a security analyst explaining real attack impact to a non-technical stakeholder — not a script formatting database fields. Your job is to investigate how far an attacker could actually move from the affected IAM node, and explain WHY each step matters and WHAT AN ATTACKER COULD CONCRETELY DO — not just report that a permission exists.

You have three tools available:
- getTrustEdges(node): returns outgoing trust edges (AssumeRole, PassRole, AttachRolePolicy) from a node.
- getAttachedPolicyDetails(node): returns the actual attached IAM policies for a role, with their raw actions and resources arrays. This is your PRIMARY signal for judging how dangerous a role is — read the actual actions and resources and reason about them in your own words.
- getResourceSensitivity(node): returns a pre-baked sensitivity tag (LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN) and reason. Use this ONLY as a secondary cross-check, not as your primary judgment.

What each trust-edge event actually MEANS (use this to explain mechanism, don't just name the event):
- AssumeRole: whoever controls the source identity's credentials/execution can call sts:AssumeRole and directly obtain the TARGET role's temporary credentials — they effectively become that role. This requires the attacker to already have usable credentials or code execution as the source.
- PassRole: the source can hand its own permissions to another AWS service on its behalf, without needing sts:AssumeRole rights on the target itself. This is a classic privilege-escalation primitive because it lets a lower-privileged identity cause a higher-privileged role to be used by a service it controls.
- AttachRolePolicy: whoever can call this against a role effectively controls what that role can do — a role that can attach policies to itself (or to other roles) can grant itself unlimited permissions, i.e. self-escalate to full account control.

Rules:
1. FIRST, check what the code-reachability investigation concluded about the vulnerability's CAPABILITY (code execution vs. denial-of-service vs. information-disclosure-only — this was classified in the prior phase, given to you in the prompt below). This determines whether the attacker can even use IAM permissions at all: code execution = attacker can act as the compromised role and use its credentials; DoS/info-disclosure-only = attacker CANNOT make AWS API calls as this role, so any IAM path from here — even a scary-looking one — is NOT actually reachable from THIS specific vulnerability. State this explicitly before tracing further.
2. If (and only if) the vulnerability grants code execution or credential access: start from the affectedNode, call getTrustEdges on it.
3. For every new node discovered, call BOTH getAttachedPolicyDetails (primary signal) AND getResourceSensitivity (secondary cross-check) before deciding whether to keep expanding.
4. Do NOT flag a hop as dangerous just because the event name is "PassRole" or "AttachRolePolicy". Reason about the SPECIFIC combination: does the attacker's current capability (from step 1) let them actually exploit this specific mechanism, and what do the destination's actual attached-policy actions/resources (not just its sensitivity tag) let them do if they succeed? Explain the mechanism in your own words each time (referencing the definitions above), not by echoing the event name.
5. CRITICAL: checking a node's sensitivity is NOT the same as knowing where the trail ends. For every new node getTrustEdges returns (not just the starting node), you MUST also call getTrustEdges on THAT node before deciding to stop — a MEDIUM-sensitivity node can still be a stepping stone to something CRITICAL one hop further. Only stop expanding a specific path once getTrustEdges on the current node returns an empty array (a true dead end), or you hit a CRITICAL/ADMIN node, or you've gone 4 hops deep on that path.
6. Decide yourself when to stop expanding overall. Do not hardcode a shallower traversal depth than rule 5 requires.
7. After finishing the trace, explicitly check whether any visited node had a pendingChange field in its sensitivity metadata. State what additional risk that pending change would introduce if merged. If no pendingChange was found on any visited node, state that explicitly.
8. FINALLY — and this is the most important rule — end your reasoning with an explicit ATTACK NARRATIVE: a plain-English, step-by-step account of "if this is exploited, here is exactly what happens and what the attacker ends up able to do," ending with why that matters to the business (e.g. what data is exposed, what damage is possible, what it would cost to remediate/disclose). If the vulnerability's capability from step 1 means the IAM path is NOT actually exploitable despite existing on paper, your attack narrative must say so explicitly and explain why, instead of describing a hypothetical chain as if it were real.

Be concise but thorough in your reasoning. Do not just list what tools returned — explain what it MEANS.`,
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
        prompt: `Based on the following investigation trace, produce a structured severity verdict. The investigation already reasoned about attack mechanism and impact in plain English — your job is to distill that into the fields below WITHOUT losing that reasoning. Do not just format field names; carry the actual analysis through.

${traceText}

Instructions:
- severity: choose CRITICAL, HIGH, MEDIUM, or LOW based on actual reachability to sensitive roles/policies, whether the vulnerable code is actually invoked, AND whether the vulnerability's capability (code execution vs. DoS vs. info-disclosure-only) actually allows exploiting any IAM path found. Not just the CVSS score, and not just "a path exists on paper."
- pathSummary: this is the most important field. Write 2-4 sentences telling the STORY of what an attacker could actually do, step by step, in plain English a non-technical stakeholder would understand — e.g. "If exploited, the attacker gains code execution inside X. Because X's role can [mechanism, in plain words] into Y, the attacker could then [concrete action], which would let them [worst realistic outcome] — exposing/damaging [specific business-relevant thing]." If the vulnerability's capability means the IAM path is NOT actually exploitable despite existing on paper (e.g. it's a DoS with no code execution), say so explicitly here and explain why, rather than describing a hypothetical chain as if it were real. Do NOT write a generic technical summary like "path from A to B via AssumeRole" — that is exactly what NOT to do.
- hops: the concrete hops traced (from -> to via event). For each hop's "reason", explain the MECHANISM (why this specific permission matters given what getAttachedPolicyDetails actually returned) — not a generic label like "has admin policy attached". Set "risky" based on whether THIS vulnerability's capability could actually exploit THIS specific mechanism, not just because the event name sounds dangerous.
- counterfactual: describe any pendingChange found on visited nodes and the additional risk it would introduce. If none, say so explicitly.
- recommendation: a concrete remediation recommendation grounded in the specific mechanism found (e.g. remove an unused broad permission, patch the specific library, add a permission boundary) — not a generic "validate your inputs" unless that is genuinely the most relevant fix.
- codeReachable: true if the vulnerable function is actually invoked in the active code path, false if it is dead/unreachable code.
- codeReachabilityReason: a short sentence explaining why the code is or isn't reachable AND what capability (code execution/DoS/info-disclosure) it grants if it is reachable, referencing the files the agent read and what they showed.`,
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
