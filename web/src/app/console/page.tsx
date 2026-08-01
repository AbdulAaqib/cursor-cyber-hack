'use client';

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { motion, useReducedMotion } from 'framer-motion';
import {
  ReactFlow,
  Background,
  Controls,
  Node,
  Edge,
  Handle,
  Position,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import ReactMarkdown from 'react-markdown';

interface Finding {
  id: string;
  package: string;
  cve: string;
  cvss: number;
  affectedNode: string;
  description: string;
}

interface Verdict {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  pathSummary: string;
  hops: Array<{
    from: string;
    to: string;
    event: string;
    risky: boolean;
    reason: string;
  }>;
  counterfactual: string;
  recommendation: string;
  codeReachable: boolean;
  codeReachabilityReason: string;
}

interface RemediationOutcome {
  ok: boolean;
  message: string;
  undoable?: boolean;
  prUrl?: string;
}

interface CombinedRemediationResult {
  aws?: RemediationOutcome;
  github?: RemediationOutcome;
}

const NODE_POSITIONS: Record<string, { x: number; y: number }> = {
  'lambda-log-processor': { x: 100, y: 300 },
  'ci-deploy-bot': { x: 100, y: 100 },
  'data-processor-role': { x: 400, y: 300 },
  'readonly-analytics-role': { x: 400, y: 100 },
  'admin-deploy-role': { x: 700, y: 300 },
  AdministratorAccess: { x: 1000, y: 300 },
  'api-gateway-service': { x: 100, y: 500 },
  'secrets-sync-role': { x: 400, y: 500 },
  'payments-data-role': { x: 700, y: 500 },
  CustomerPaymentsDataAccess: { x: 1000, y: 500 },
};

const FINDING_CHAINS: Record<string, { nodes: string[]; edgeIds: string[] }> = {
  'SNYK-2026-001': {
    nodes: ['lambda-log-processor', 'data-processor-role', 'admin-deploy-role', 'AdministratorAccess'],
    edgeIds: ['e1', 'e2', 'e3'],
  },
  'SNYK-2026-002': {
    nodes: ['ci-deploy-bot', 'readonly-analytics-role'],
    edgeIds: ['e4'],
  },
  'SNYK-2026-003': {
    nodes: ['api-gateway-service', 'secrets-sync-role', 'payments-data-role', 'CustomerPaymentsDataAccess'],
    edgeIds: ['e5', 'e6', 'e7'],
  },
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#D93B4A',
  HIGH: '#E07C2E',
  MEDIUM: '#C99A1E',
  LOW: '#2E9E6B',
  UNKNOWN: '#5B6478',
};

function CustomNode({
  data,
}: {
  data: { label: string; sensitivity?: string; visited?: boolean; active?: boolean };
}) {
  const color = data.visited ? SEVERITY_COLORS[data.sensitivity ?? 'UNKNOWN'] : '#B0B8C9';
  return (
    <div
      className={`rounded border px-3 py-2 font-mono text-xs transition-colors duration-500 ${
        data.active ? 'animate-pulse-glow' : ''
      }`}
      style={{
        borderColor: data.active ? '#E89B2E' : color,
        backgroundColor: data.visited ? '#FFFFFF' : '#E8ECF4',
        color: data.visited ? '#10182B' : '#5B6478',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div>{data.label}</div>
      {data.visited && data.sensitivity && (
        <div className="text-[10px] mt-1 font-semibold tracking-wide" style={{ color }}>
          {data.sensitivity}
        </div>
      )}
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = { custom: CustomNode };

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-critical/15 border-critical text-critical',
  HIGH: 'bg-high/15 border-high text-high',
  MEDIUM: 'bg-medium/15 border-medium text-medium',
  LOW: 'bg-low/15 border-low text-low',
};

const VERDICT_GLOW: Record<string, { spread: string; color: string }> = {
  CRITICAL: { spread: '0 0 32px 8px', color: 'rgba(217, 59, 74, 0.60)' },
  HIGH: { spread: '0 0 28px 6px', color: 'rgba(224, 124, 46, 0.55)' },
  MEDIUM: { spread: '0 0 24px 5px', color: 'rgba(201, 154, 30, 0.50)' },
  LOW: { spread: '0 0 20px 4px', color: 'rgba(46, 158, 107, 0.45)' },
};

const GITHUB_PREVIEW: Record<string, string> = {
  'SNYK-2026-001':
    'Add input validation to `processLogs` before calling `parseLogEntry` -- rejects non-string entries and entries exceeding 1MB.',
  'SNYK-2026-002':
    'Remove the dead `padString` import from `string-pad-utility` entirely. The function is not called in the active code path.',
  'SNYK-2026-003':
    'Add URL validation to `fetchExternal` to block internal/link-local IP ranges (e.g. 169.254.169.254) and restrict requests to an allow-list of approved external domains.',
};

// Client-side mirror of the AWS target map for display / filtering
const AWS_TARGET_DISPLAY: Record<string, { roleName: string; policyArn: string; policyLabel: string }> = {
  'SNYK-2026-001': {
    roleName: 'admin-deploy-role',
    policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
    policyLabel: 'AdministratorAccess',
  },
  'SNYK-2026-003': {
    roleName: 'payments-data-role',
    policyArn: 'arn:aws:iam::110480666916:policy/CustomerPaymentsDataAccess',
    policyLabel: 'CustomerPaymentsDataAccess',
  },
};

async function readSSELogs(
  res: Response,
  onLog: (msg: string) => void,
): Promise<{ ok: boolean; error?: string; prUrl?: string }> {
  if (!res.body) {
    return { ok: false, error: 'No response body' };
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let finalResult: { ok: boolean; error?: string; prUrl?: string } = { ok: false, error: 'Stream ended without done event' };

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const parts = buffer.split('\n\n');
    buffer = parts.pop() ?? '';
    for (const part of parts) {
      const line = part.trim();
      if (!line.startsWith('data: ')) continue;
      const jsonStr = line.slice(6);
      try {
        const event = JSON.parse(jsonStr);
        if (event.type === 'log') {
          onLog(event.message);
        }
        if (event.type === 'done') {
          finalResult = {
            ok: event.ok,
            error: event.error,
            prUrl: event.prUrl,
          };
        }
      } catch {
        // ignore parse errors
      }
    }
  }

  return finalResult;
}

function ConsolePageInner() {
  const reduced = useReducedMotion();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string>('');
  const [investigating, setInvestigating] = useState(false);
  const [reasoning, setReasoning] = useState('');
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [visitedNodes, setVisitedNodes] = useState<Set<string>>(new Set());
  const [knownEdges, setKnownEdges] = useState<Set<string>>(new Set());
  const [nodeSensitivities, setNodeSensitivities] = useState<Record<string, string>>({});
  const [activeNode, setActiveNode] = useState<string | null>(null);
  const reasoningRef = useRef<HTMLDivElement>(null);

  // Remediation state
  const [remediationPreviewOpen, setRemediationPreviewOpen] = useState(false);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [remediationResult, setRemediationResult] = useState<CombinedRemediationResult | null>(null);
  const [remediationLogs, setRemediationLogs] = useState<string[]>([]);
  const [awsActionFindingId, setAwsActionFindingId] = useState<string | null>(null);
  const logsRef = useRef<HTMLDivElement>(null);

  const searchParams = useSearchParams();
  const preselectedFinding = searchParams.get('finding');

  useEffect(() => {
    fetch('/api/findings')
      .then((r) => r.json())
      .then((data) => {
        setFindings(data);
        if (preselectedFinding && data.some((f: Finding) => f.id === preselectedFinding)) {
          setSelectedFindingId(preselectedFinding);
        } else if (data.length > 0) {
          setSelectedFindingId(data[0].id);
        }
      });
  }, [preselectedFinding]);

  useEffect(() => {
    if (reasoningRef.current) {
      reasoningRef.current.scrollTop = reasoningRef.current.scrollHeight;
    }
  }, [reasoning]);

  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }
  }, [remediationLogs]);

  const activeChain = selectedFindingId ? FINDING_CHAINS[selectedFindingId] : undefined;

  const nodes: Node[] = useMemo(() => {
    const allNodes = activeChain ? activeChain.nodes : Object.keys(NODE_POSITIONS);
    return allNodes.map((id) => ({
      id,
      type: 'custom',
      position: NODE_POSITIONS[id],
      data: {
        label: id,
        sensitivity: nodeSensitivities[id],
        visited: visitedNodes.has(id),
        active: activeNode === id,
      },
    }));
  }, [visitedNodes, nodeSensitivities, activeNode, activeChain]);

  const edges: Edge[] = useMemo(() => {
    const allEdges = [
      { id: 'e1', source: 'lambda-log-processor', target: 'data-processor-role', label: 'AssumeRole' },
      { id: 'e2', source: 'data-processor-role', target: 'admin-deploy-role', label: 'PassRole' },
      { id: 'e3', source: 'admin-deploy-role', target: 'AdministratorAccess', label: 'AttachRolePolicy' },
      { id: 'e4', source: 'ci-deploy-bot', target: 'readonly-analytics-role', label: 'AssumeRole' },
      { id: 'e5', source: 'api-gateway-service', target: 'secrets-sync-role', label: 'AssumeRole' },
      { id: 'e6', source: 'secrets-sync-role', target: 'payments-data-role', label: 'AssumeRole' },
      { id: 'e7', source: 'payments-data-role', target: 'CustomerPaymentsDataAccess', label: 'AttachRolePolicy' },
    ];
    const baseEdges = activeChain
      ? allEdges.filter((e) => activeChain.edgeIds.includes(e.id))
      : allEdges;
    return baseEdges.map((e) => ({
      ...e,
      animated: knownEdges.has(e.id),
      style: {
        stroke: knownEdges.has(e.id) ? '#E89B2E' : '#B0B8C9',
        strokeWidth: knownEdges.has(e.id) ? 2 : 1,
        transition: 'all 0.5s',
      },
      labelStyle: {
        fill: knownEdges.has(e.id) ? '#10182B' : '#5B6478',
        fontSize: 11,
        fontFamily: 'var(--font-mono)',
        fontWeight: knownEdges.has(e.id) ? 600 : 400,
      },
      labelBgStyle: { fill: '#F7F9FC', fillOpacity: 0.85 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: knownEdges.has(e.id) ? '#E89B2E' : '#B0B8C9',
      },
    }));
  }, [knownEdges, activeChain]);

  const handleInvestigate = useCallback(async () => {
    if (!selectedFindingId) return;
    setInvestigating(true);
    setReasoning('');
    setVerdict(null);
    setVisitedNodes(new Set());
    setKnownEdges(new Set());
    setNodeSensitivities({});
    setActiveNode(null);
    setRemediationPreviewOpen(false);
    setRemediationResult(null);
    setRemediationLogs([]);
    setAwsActionFindingId(null);

    const res = await fetch('/api/investigate', {
      method: 'POST',
      body: JSON.stringify({ findingId: selectedFindingId }),
    });

    if (!res.body) {
      setInvestigating(false);
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split('\n\n');
      buffer = parts.pop() ?? '';
      for (const part of parts) {
        const line = part.trim();
        if (!line.startsWith('data: ')) continue;
        const jsonStr = line.slice(6);
        try {
          const event = JSON.parse(jsonStr);
          if (event.type === 'text-delta') {
            setReasoning((prev) => prev + event.text);
          }
          if (event.type === 'tool-result') {
            if (event.toolName === 'getTrustEdges') {
              const results = event.output as Array<{ target: string; event: string }>;
              const sourceNode = (event.input as { node: string }).node;
              setActiveNode(sourceNode);
              setVisitedNodes((prev) => {
                const next = new Set(prev);
                next.add(sourceNode);
                for (const r of results) {
                  next.add(r.target);
                }
                return next;
              });
              setKnownEdges((prev) => {
                const next = new Set(prev);
                const edgeIdMap: Record<string, string> = {
                  'lambda-log-processor->data-processor-role': 'e1',
                  'data-processor-role->admin-deploy-role': 'e2',
                  'admin-deploy-role->AdministratorAccess': 'e3',
                  'ci-deploy-bot->readonly-analytics-role': 'e4',
                  'api-gateway-service->secrets-sync-role': 'e5',
                  'secrets-sync-role->payments-data-role': 'e6',
                  'payments-data-role->CustomerPaymentsDataAccess': 'e7',
                };
                for (const r of results) {
                  const key = `${sourceNode}->${r.target}`;
                  const edgeId = edgeIdMap[key];
                  if (edgeId) next.add(edgeId);
                }
                return next;
              });
            }
            if (event.toolName === 'getResourceSensitivity') {
              const node = (event.input as { node: string }).node;
              const out = event.output as { sensitivity: string };
              setActiveNode(node);
              setNodeSensitivities((prev) => ({ ...prev, [node]: out.sensitivity }));
              setVisitedNodes((prev) => {
                const next = new Set(prev);
                next.add(node);
                return next;
              });
            }
          }
          if (event.type === 'verdict') {
            setVerdict(event.data as Verdict);
            setActiveNode(null);
          }
        } catch {
          // ignore parse errors
        }
      }
    }

    setInvestigating(false);
    setActiveNode(null);
  }, [selectedFindingId]);

  const selectedFinding = findings.find((f) => f.id === selectedFindingId);
  const activeAwsTarget = selectedFindingId ? AWS_TARGET_DISPLAY[selectedFindingId] : undefined;
  const showAwsAction =
    verdict &&
    (verdict.severity === 'CRITICAL' || verdict.severity === 'HIGH') &&
    activeAwsTarget !== undefined;

  const handleConfirmRemediation = useCallback(async () => {
    setRemediationLoading(true);
    setRemediationResult(null);
    setRemediationLogs([]);
    setAwsActionFindingId(null);

    const result: CombinedRemediationResult = {};
    const addLog = (prefix: string, msg: string) => {
      setRemediationLogs((prev) => [...prev, `[${prefix}] ${msg}`]);
    };

    if (showAwsAction && activeAwsTarget) {
      const awsRes = await fetch('/api/remediate/aws', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'detach', findingId: selectedFindingId }),
      });
      const awsResult = await readSSELogs(awsRes, (msg) => addLog('AWS', msg));
      if (awsResult.ok) {
        setAwsActionFindingId(selectedFindingId);
        result.aws = {
          ok: true,
          message: `${activeAwsTarget.policyLabel} detached from ${activeAwsTarget.roleName}`,
          undoable: true,
        };
      } else {
        result.aws = { ok: false, message: awsResult.error ?? 'Unknown error' };
      }
    }

    const githubRes = await fetch('/api/remediate/github', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findingId: selectedFindingId }),
    });
    const githubResult = await readSSELogs(githubRes, (msg) => addLog('GitHub', msg));
    if (githubResult.ok && githubResult.prUrl) {
      result.github = {
        ok: true,
        message: 'Pull request opened successfully',
        prUrl: githubResult.prUrl,
      };
    } else {
      result.github = { ok: false, message: githubResult.error ?? 'Unknown error' };
    }

    setRemediationResult(result);
    setRemediationLoading(false);
  }, [selectedFindingId, showAwsAction, activeAwsTarget]);

  const handleUndoAws = useCallback(async () => {
    setRemediationLoading(true);
    const addLog = (prefix: string, msg: string) => {
      setRemediationLogs((prev) => [...prev, `[${prefix}] ${msg}`]);
    };

    const targetFindingId = awsActionFindingId ?? selectedFindingId;
    const target = targetFindingId ? AWS_TARGET_DISPLAY[targetFindingId] : undefined;

    const res = await fetch('/api/remediate/aws', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'reattach', findingId: targetFindingId }),
    });
    const result = await readSSELogs(res, (msg) => addLog('AWS', msg));
    setRemediationResult((prev) => {
      if (!prev) return prev;
      const label = target?.policyLabel ?? 'policy';
      const role = target?.roleName ?? 'role';
      return {
        ...prev,
        aws: result.ok
          ? { ok: true, message: `${label} re-attached to ${role}`, undoable: false }
          : { ok: false, message: result.error ?? 'Unknown error' },
      };
    });
    setRemediationLoading(false);
  }, [awsActionFindingId, selectedFindingId]);

  return (
    <div className="flex flex-col h-[calc(100vh-48px)] bg-background text-foreground font-sans">
      <header className="flex items-center justify-between gap-6 border-b border-border-hairline bg-panel px-6 py-3">
        <div className="flex items-center gap-2">
          <span
            className={`h-2 w-2 rounded-full bg-accent ${
              investigating ? 'animate-status-pulse' : ''
            }`}
          />
          <span className="font-mono text-xs text-muted">
            {investigating ? 'LIVE INVESTIGATION RUNNING' : 'READY'}
          </span>
        </div>
        <p className="hidden md:block text-xs text-muted font-mono">
          ~96,000 permissions per employee. No human traces reachability at that scale manually.
        </p>
      </header>

      <div className="flex flex-wrap items-center gap-3 border-b border-border-hairline bg-background px-6 py-3">
        <label className="font-mono text-[11px] uppercase tracking-wider text-muted">
          Finding
        </label>
        <select
          className="rounded border border-border-hairline bg-panel px-3 py-1.5 font-mono text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-accent"
          style={{ backgroundColor: 'var(--panel)', color: 'var(--foreground)' }}
          value={selectedFindingId}
          onChange={(e) => setSelectedFindingId(e.target.value)}
          disabled={investigating}
        >
          {findings.map((f) => (
            <option
              key={f.id}
              value={f.id}
              style={{ backgroundColor: 'var(--panel)', color: 'var(--foreground)' }}
            >
              {f.id} -- {f.package} (CVSS {f.cvss})
            </option>
          ))}
        </select>
        {selectedFinding && (
          <span className="hidden lg:inline text-xs text-muted truncate max-w-md">
            {selectedFinding.description}
          </span>
        )}
        <button
          onClick={handleInvestigate}
          disabled={investigating || !selectedFindingId}
          className="rounded bg-accent px-4 py-1.5 font-mono text-xs font-semibold text-[#10182B] transition-opacity hover:opacity-90 disabled:opacity-40 sm:ml-auto w-full sm:w-auto mt-2 sm:mt-0"
        >
          {investigating ? 'INVESTIGATING...' : 'INVESTIGATE'}
        </button>
      </div>

      <main className="flex-1 flex flex-col lg:flex-row overflow-hidden">
        <div className="flex-1 bg-background h-[45vh] lg:h-auto min-h-0">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            attributionPosition="bottom-left"
            proOptions={{ hideAttribution: false }}
          >
            <Background gap={18} size={1} color="#E3E8F0" />
            <Controls className="[&>button]:!bg-panel [&>button]:!border-border-hairline [&>button]:!fill-foreground" />
          </ReactFlow>
        </div>

        <aside className="w-full lg:w-[420px] flex flex-col border-t lg:border-t-0 lg:border-l border-border-hairline bg-panel min-h-0">
          <div className="px-4 py-2 flex items-center gap-2 border-b border-border-hairline">
            <span className="text-[11px] font-mono uppercase tracking-wider text-muted">
              Agent reasoning
            </span>
          </div>
          <div
            ref={reasoningRef}
            className="console-scroll flex-1 overflow-auto p-4 font-mono text-[12px] leading-relaxed text-foreground/90"
          >
            {reasoning ? (
              <>
                <ReactMarkdown
                  components={{
                    h1: ({ children }) => <h1 className="text-[13px] font-bold mb-1 mt-2">{children}</h1>,
                    h2: ({ children }) => <h2 className="text-[12px] font-bold mb-1 mt-2">{children}</h2>,
                    h3: ({ children }) => <h3 className="text-[11px] font-bold mb-1 mt-1.5">{children}</h3>,
                    p: ({ children }) => <p className="mb-1.5">{children}</p>,
                    ul: ({ children }) => <ul className="list-disc pl-4 mb-1.5">{children}</ul>,
                    ol: ({ children }) => <ol className="list-decimal pl-4 mb-1.5">{children}</ol>,
                    li: ({ children }) => <li className="mb-0.5">{children}</li>,
                    strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
                    code: ({ children }) => <code className="bg-border-hairline/30 rounded px-1 py-0.5 text-[11px]">{children}</code>,
                    pre: ({ children }) => <pre className="bg-border-hairline/20 rounded p-2 mb-1.5 overflow-auto">{children}</pre>,
                  }}
                >
                  {reasoning}
                </ReactMarkdown>
                {investigating && <span className="cursor-blink" />}
              </>
            ) : (
              <span className="text-muted italic">
                &gt; awaiting investigation -- select a finding and hit INVESTIGATE
                {investigating && <span className="cursor-blink" />}
              </span>
            )}
          </div>

          {verdict && (
            <motion.div
              key={verdict.severity}
              initial={{
                opacity: 0,
                y: 16,
                boxShadow: `${VERDICT_GLOW[verdict.severity].spread} ${VERDICT_GLOW[verdict.severity].color}`,
              }}
              animate={{
                opacity: 1,
                y: 0,
                boxShadow: '0 0 0 0 transparent',
              }}
              transition={{
                duration: reduced ? 0 : 0.7,
                ease: 'easeOut',
              }}
              className="border-t border-border-hairline p-4 max-h-[55%] overflow-auto console-scroll"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-[11px] font-mono uppercase tracking-wider text-muted">
                  Verdict
                </span>
                <span
                  className={`rounded border px-2 py-0.5 font-mono text-[11px] font-bold ${SEVERITY_BADGE[verdict.severity]}`}
                >
                  {verdict.severity}
                </span>
              </div>

              <p className="text-sm leading-relaxed text-foreground mb-3">{verdict.pathSummary}</p>

              <div
                className={`mb-3 inline-flex items-center gap-2 rounded border px-2 py-1 font-mono text-[11px] ${
                  verdict.codeReachable
                    ? 'border-high/40 bg-high/10 text-high'
                    : 'border-border-hairline bg-background text-muted'
                }`}
              >
                <span className="font-semibold">
                  CODE {verdict.codeReachable ? 'REACHABLE' : 'NOT REACHABLE'}
                </span>
              </div>
              <p className="text-xs text-muted mb-4">{verdict.codeReachabilityReason}</p>

              <div className="space-y-3">
                <div>
                  <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted mb-1.5">
                    Hops
                  </div>
                  <ul className="space-y-2">
                    {verdict.hops.map((h, i) => (
                      <li key={i} className="text-xs border-l-2 border-border-hairline pl-2">
                        <div className="font-mono">
                          <span className="text-foreground">{h.from}</span>
                          <span className="text-muted"> &rarr; </span>
                          <span className="text-foreground">{h.to}</span>
                          <span className="text-muted"> ({h.event}) </span>
                          {h.risky ? (
                            <span className="text-critical font-semibold">risky</span>
                          ) : (
                            <span className="text-low font-semibold">safe</span>
                          )}
                        </div>
                        <div className="text-muted mt-0.5">{h.reason}</div>
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted mb-1">
                    Counterfactual
                  </div>
                  <p className="text-xs text-foreground/80">{verdict.counterfactual}</p>
                </div>
                <div>
                  <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted mb-1">
                    Recommendation
                  </div>
                  <p className="text-xs text-foreground/80">{verdict.recommendation}</p>
                </div>
              </div>
            </motion.div>
          )}

          {/* -- Remediation Section -- */}
          {verdict && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{
                duration: reduced ? 0 : 0.4,
                ease: 'easeOut',
                delay: reduced ? 0 : 0.2,
              }}
              className="border-t border-border-hairline p-4"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-[11px] font-mono uppercase tracking-wider text-muted">
                  Remediation
                </span>
              </div>

              {/* Action button (stage 1) */}
              {!remediationPreviewOpen && !remediationResult && (
                <div className="space-y-2">
                  <button
                    onClick={() => {
                      setRemediationPreviewOpen(true);
                      setRemediationResult(null);
                      setRemediationLogs([]);
                    }}
                    disabled={investigating}
                    className="w-full rounded border border-accent/40 bg-accent/10 px-3 py-2 font-mono text-xs font-semibold text-accent transition-opacity hover:opacity-80 disabled:opacity-40"
                  >
                    PREPARE REMEDIATION
                  </button>
                </div>
              )}

              {/* Preview panel (stage 2) */}
              {remediationPreviewOpen && !remediationResult && (
                <div className="space-y-3">
                  <div className="rounded border border-border-hairline bg-background p-3">
                    <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted mb-2">
                      Preview
                    </div>
                    <div className="space-y-2">
                      {showAwsAction && activeAwsTarget && (
                        <div className="flex items-start gap-2">
                          <span className="mt-0.5 h-1.5 w-1.5 rounded-full bg-critical shrink-0" />
                          <div>
                            <p className="text-xs text-foreground/90 font-semibold">
                              Step 1: Detach {activeAwsTarget.policyLabel}
                            </p>
                            <p className="text-xs text-foreground/90">
                              Detach{' '}
                              <code className="font-mono text-accent">
                                {activeAwsTarget.policyArn}
                              </code>{' '}
                              from role{' '}
                              <code className="font-mono text-accent">{activeAwsTarget.roleName}</code>.
                            </p>
                            <p className="text-[11px] text-muted">
                              You can re-attach it immediately afterward if needed.
                            </p>
                          </div>
                        </div>
                      )}
                      <div className="flex items-start gap-2">
                        <span className="mt-0.5 h-1.5 w-1.5 rounded-full bg-accent shrink-0" />
                        <div>
                          <p className="text-xs text-foreground/90 font-semibold">
                            {showAwsAction ? 'Step 2: Open a GitHub PR' : 'Step 1: Open a GitHub PR'}
                          </p>
                          <p className="text-xs text-foreground/90">
                            Open a new pull request on{' '}
                            <code className="font-mono text-accent">
                              {process.env.NEXT_PUBLIC_GITHUB_REPO ?? 'this repository'}
                            </code>{' '}
                            with the following fix:
                          </p>
                          <p className="text-xs text-foreground/80 border-l-2 border-accent/40 pl-2 mt-1">
                            {GITHUB_PREVIEW[selectedFindingId] ?? 'Custom fix for this finding.'}
                          </p>
                          <p className="text-[11px] text-muted">
                            The PR will <strong>not</strong> auto-merge. A human must review and merge it manually.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => {
                        void handleConfirmRemediation();
                      }}
                      disabled={remediationLoading}
                      className="flex-1 rounded bg-accent px-3 py-2 font-mono text-xs font-semibold text-[#10182B] transition-opacity hover:opacity-90 disabled:opacity-40"
                    >
                      {remediationLoading ? 'APPLYING...' : 'CONFIRM & APPLY'}
                    </button>
                    <button
                      onClick={() => {
                        setRemediationPreviewOpen(false);
                        setRemediationResult(null);
                        setRemediationLogs([]);
                      }}
                      disabled={remediationLoading}
                      className="rounded border border-border-hairline bg-panel px-3 py-2 font-mono text-xs text-muted transition-opacity hover:opacity-80 disabled:opacity-40"
                    >
                      CANCEL
                    </button>
                  </div>
                </div>
              )}

              {/* Live log panel */}
              {remediationLoading && (
                <div className="mb-3">
                  <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted mb-1.5">
                    Remediation Log
                  </div>
                  <div
                    ref={logsRef}
                    className="console-scroll rounded border border-border-hairline bg-background p-3 font-mono text-[11px] leading-relaxed text-muted whitespace-pre-wrap max-h-40 overflow-auto"
                  >
                    {remediationLogs.length === 0 ? (
                      <span className="italic">Waiting for first log line...</span>
                    ) : (
                      remediationLogs.map((line, i) => (
                        <div key={i} className="mb-0.5">{line}</div>
                      ))
                    )}
                    <span className="cursor-blink" />
                  </div>
                </div>
              )}

              {/* Result state */}
              {remediationResult && (
                <div className="space-y-3">
                  {remediationResult.aws && (
                    <div
                      className={`rounded border px-3 py-2 ${
                        remediationResult.aws.ok
                          ? 'border-low/40 bg-low/10'
                          : 'border-critical/40 bg-critical/10'
                      }`}
                    >
                      <div
                        className={`text-xs font-mono font-semibold ${
                          remediationResult.aws.ok ? 'text-low' : 'text-critical'
                        }`}
                      >
                        {remediationResult.aws.ok ? 'AWS SUCCESS' : 'AWS ERROR'}
                      </div>
                      <p className="text-xs text-foreground/90 mt-1">{remediationResult.aws.message}</p>
                    </div>
                  )}

                  {remediationResult.github && (
                    <div
                      className={`rounded border px-3 py-2 ${
                        remediationResult.github.ok
                          ? 'border-low/40 bg-low/10'
                          : 'border-critical/40 bg-critical/10'
                      }`}
                    >
                      <div
                        className={`text-xs font-mono font-semibold ${
                          remediationResult.github.ok ? 'text-low' : 'text-critical'
                        }`}
                      >
                        {remediationResult.github.ok ? 'GITHUB SUCCESS' : 'GITHUB ERROR'}
                      </div>
                      <p className="text-xs text-foreground/90 mt-1">{remediationResult.github.message}</p>
                      {remediationResult.github.prUrl && (
                        <a
                          href={remediationResult.github.prUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-accent underline hover:opacity-80 mt-1 inline-block"
                        >
                          {remediationResult.github.prUrl}
                        </a>
                      )}
                    </div>
                  )}

                  <div className="flex gap-2">
                    {remediationResult.aws?.undoable && (
                      <button
                        onClick={() => handleUndoAws()}
                        disabled={remediationLoading}
                        className="flex-1 rounded border border-accent/40 bg-accent/10 px-3 py-2 font-mono text-xs font-semibold text-accent transition-opacity hover:opacity-80 disabled:opacity-40"
                      >
                        {remediationLoading ? 'APPLYING...' : 'UNDO -- RE-ATTACH POLICY'}
                      </button>
                    )}
                    <button
                      onClick={() => {
                        setRemediationPreviewOpen(false);
                        setRemediationResult(null);
                        setRemediationLogs([]);
                      }}
                      className="rounded border border-border-hairline bg-panel px-3 py-2 font-mono text-xs text-muted transition-opacity hover:opacity-80"
                    >
                      RUN ANOTHER
                    </button>
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </aside>
      </main>

      <footer className="border-t border-border-hairline bg-panel px-6 py-2 text-[11px] font-mono text-muted">
        Lightweight, agent-driven alternative to attack-path-analysis platforms like Wiz/Orca -- built to run in minutes with zero infrastructure.
      </footer>
    </div>
  );
}

export default function ConsolePage() {
  return (
    <Suspense fallback={
      <div className="flex h-[calc(100vh-48px)] items-center justify-center bg-background text-muted font-mono text-xs">
        Loading console...
      </div>
    }>
      <ConsolePageInner />
    </Suspense>
  );
}
