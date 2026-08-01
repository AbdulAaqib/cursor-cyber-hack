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

type RemediationMode = 'aws' | 'github' | null;

interface RemediationResult {
  type: 'success' | 'error';
  message: string;
  prUrl?: string;
  undoable?: boolean;
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

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#f0465a',
  HIGH: '#f5943b',
  MEDIUM: '#f0c43b',
  LOW: '#3ecf8e',
  UNKNOWN: '#6b7686',
};

function CustomNode({
  data,
}: {
  data: { label: string; sensitivity?: string; visited?: boolean; active?: boolean };
}) {
  const color = data.visited ? SEVERITY_COLORS[data.sensitivity ?? 'UNKNOWN'] : '#3a4453';
  return (
    <div
      className={`rounded border px-3 py-2 font-mono text-xs transition-colors duration-500 ${
        data.active ? 'animate-pulse-glow' : ''
      }`}
      style={{
        borderColor: data.active ? '#22d3c7' : color,
        backgroundColor: data.visited ? '#121821' : '#0d131b',
        color: data.visited ? '#e4e9f0' : '#4b5566',
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
  CRITICAL: { spread: '0 0 32px 8px', color: 'rgba(240, 70, 90, 0.60)' },
  HIGH: { spread: '0 0 28px 6px', color: 'rgba(245, 148, 59, 0.55)' },
  MEDIUM: { spread: '0 0 24px 5px', color: 'rgba(240, 196, 59, 0.50)' },
  LOW: { spread: '0 0 20px 4px', color: 'rgba(62, 207, 142, 0.45)' },
};

const GITHUB_PREVIEW: Record<string, string> = {
  'SNYK-2026-001':
    'Add input validation to `processLogs` before calling `parseLogEntry` -- rejects non-string entries and entries exceeding 1MB.',
  'SNYK-2026-002':
    'Remove the dead `padString` import from `string-pad-utility` entirely. The function is not called in the active code path.',
  'SNYK-2026-003':
    'Add URL validation to `fetchExternal` to block internal/link-local IP ranges (e.g. 169.254.169.254) and restrict requests to an allow-list of approved external domains.',
};

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
  const [remediationMode, setRemediationMode] = useState<RemediationMode>(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [remediationResult, setRemediationResult] = useState<RemediationResult | null>(null);
  const [remediationLogs, setRemediationLogs] = useState<string[]>([]);
  const [activeRemediationAction, setActiveRemediationAction] = useState<'aws' | 'github' | null>(null);
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

  const nodes: Node[] = useMemo(() => {
    const allNodes = Object.keys(NODE_POSITIONS);
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
  }, [visitedNodes, nodeSensitivities, activeNode]);

  const edges: Edge[] = useMemo(() => {
    const baseEdges = [
      { id: 'e1', source: 'lambda-log-processor', target: 'data-processor-role', label: 'AssumeRole' },
      { id: 'e2', source: 'data-processor-role', target: 'admin-deploy-role', label: 'PassRole' },
      { id: 'e3', source: 'admin-deploy-role', target: 'AdministratorAccess', label: 'AttachRolePolicy' },
      { id: 'e4', source: 'ci-deploy-bot', target: 'readonly-analytics-role', label: 'AssumeRole' },
      { id: 'e5', source: 'api-gateway-service', target: 'secrets-sync-role', label: 'AssumeRole' },
      { id: 'e6', source: 'secrets-sync-role', target: 'payments-data-role', label: 'AssumeRole' },
      { id: 'e7', source: 'payments-data-role', target: 'CustomerPaymentsDataAccess', label: 'AttachRolePolicy' },
    ];
    return baseEdges.map((e) => ({
      ...e,
      animated: knownEdges.has(e.id),
      style: {
        stroke: knownEdges.has(e.id) ? '#22d3c7' : '#242e3c',
        strokeWidth: knownEdges.has(e.id) ? 2 : 1,
        transition: 'all 0.5s',
      },
      labelStyle: {
        fill: knownEdges.has(e.id) ? '#e4e9f0' : '#4b5566',
        fontSize: 11,
        fontFamily: 'var(--font-mono)',
        fontWeight: knownEdges.has(e.id) ? 600 : 400,
      },
      labelBgStyle: { fill: '#0a0e14', fillOpacity: 0.85 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: knownEdges.has(e.id) ? '#22d3c7' : '#242e3c',
      },
    }));
  }, [knownEdges]);

  const handleInvestigate = useCallback(async () => {
    if (!selectedFindingId) return;
    setInvestigating(true);
    setReasoning('');
    setVerdict(null);
    setVisitedNodes(new Set());
    setKnownEdges(new Set());
    setNodeSensitivities({});
    setActiveNode(null);
    setRemediationMode(null);
    setRemediationResult(null);
    setRemediationLoading(false);
    setRemediationLogs([]);
    setActiveRemediationAction(null);

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

  const handleAwsRemediate = useCallback(
    async (action: 'detach' | 'reattach') => {
      setRemediationLoading(true);
      setRemediationResult(null);
      setRemediationLogs([]);
      setActiveRemediationAction('aws');

      const res = await fetch('/api/remediate/aws', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      });

      if (!res.body) {
        setRemediationLoading(false);
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
            if (event.type === 'log') {
              setRemediationLogs((prev) => [...prev, event.message]);
            }
            if (event.type === 'done') {
              if (event.ok) {
                setRemediationResult({
                  type: 'success',
                  message:
                    action === 'detach'
                      ? 'AdministratorAccess detached from admin-deploy-role'
                      : 'AdministratorAccess re-attached to admin-deploy-role',
                  undoable: action === 'detach',
                });
              } else {
                setRemediationResult({
                  type: 'error',
                  message: event.error ?? 'Unknown error',
                });
              }
            }
          } catch {
            // ignore parse errors
          }
        }
      }

      setRemediationLoading(false);
    },
    [],
  );

  const handleGithubRemediate = useCallback(async () => {
    setRemediationLoading(true);
    setRemediationResult(null);
    setRemediationLogs([]);
    setActiveRemediationAction('github');

    const res = await fetch('/api/remediate/github', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findingId: selectedFindingId }),
    });

    if (!res.body) {
      setRemediationLoading(false);
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
          if (event.type === 'log') {
            setRemediationLogs((prev) => [...prev, event.message]);
          }
          if (event.type === 'done') {
            if (event.ok && event.prUrl) {
              setRemediationResult({
                type: 'success',
                message: 'Pull request opened successfully',
                prUrl: event.prUrl,
              });
            } else {
              setRemediationResult({
                type: 'error',
                message: event.error ?? 'Unknown error',
              });
            }
          }
        } catch {
          // ignore parse errors
        }
      }
    }

    setRemediationLoading(false);
  }, [selectedFindingId]);

  const selectedFinding = findings.find((f) => f.id === selectedFindingId);
  const showAwsAction = verdict && (verdict.severity === 'CRITICAL' || verdict.severity === 'HIGH');

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
          value={selectedFindingId}
          onChange={(e) => setSelectedFindingId(e.target.value)}
          disabled={investigating}
        >
          {findings.map((f) => (
            <option key={f.id} value={f.id}>
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
          className="rounded bg-accent px-4 py-1.5 font-mono text-xs font-semibold text-[#0A0E14] transition-opacity hover:opacity-90 disabled:opacity-40 sm:ml-auto w-full sm:w-auto mt-2 sm:mt-0"
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
            <Background gap={18} size={1} color="#161d28" />
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
            className="console-scroll flex-1 overflow-auto p-4 font-mono text-[12px] leading-relaxed text-foreground/90 whitespace-pre-wrap"
          >
            {reasoning ? (
              <>
                {reasoning}
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

              {/* Action buttons (stage 1) */}
              {remediationMode === null && !remediationResult && (
                <div className="space-y-2">
                  {showAwsAction && (
                    <button
                      onClick={() => {
                        setRemediationMode('aws');
                        setRemediationResult(null);
                        setRemediationLogs([]);
                        setActiveRemediationAction(null);
                      }}
                      disabled={investigating}
                      className="w-full rounded border border-critical/40 bg-critical/10 px-3 py-2 font-mono text-xs font-semibold text-critical transition-opacity hover:opacity-80 disabled:opacity-40"
                    >
                      PREPARE AWS FIX -- DETACH ADMIN POLICY
                    </button>
                  )}
                  <button
                    onClick={() => {
                      setRemediationMode('github');
                      setRemediationResult(null);
                      setRemediationLogs([]);
                      setActiveRemediationAction(null);
                    }}
                    disabled={investigating}
                    className="w-full rounded border border-accent/40 bg-accent/10 px-3 py-2 font-mono text-xs font-semibold text-accent transition-opacity hover:opacity-80 disabled:opacity-40"
                  >
                    PREPARE GITHUB FIX -- OPEN PR
                  </button>
                </div>
              )}

              {/* Preview panel (stage 2) */}
              {remediationMode !== null && !remediationResult && (
                <div className="space-y-3">
                  <div className="rounded border border-border-hairline bg-background p-3">
                    <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted mb-2">
                      Preview
                    </div>
                    {remediationMode === 'aws' && (
                      <div className="space-y-2">
                        <p className="text-xs text-foreground/90">
                          This will detach{' '}
                          <code className="font-mono text-accent">
                            arn:aws:iam::aws:policy/AdministratorAccess
                          </code>{' '}
                          from role{' '}
                          <code className="font-mono text-accent">admin-deploy-role</code> in your
                          AWS account.
                        </p>
                        <p className="text-[11px] text-muted">
                          You can re-attach it immediately afterward if needed.
                        </p>
                      </div>
                    )}
                    {remediationMode === 'github' && (
                      <div className="space-y-2">
                        <p className="text-xs text-foreground/90">
                          This will open a new pull request on{' '}
                          <code className="font-mono text-accent">{process.env.NEXT_PUBLIC_GITHUB_REPO ?? 'this repository'}</code>{' '}
                          with the following fix:
                        </p>
                        <p className="text-xs text-foreground/80 border-l-2 border-accent/40 pl-2">
                          {GITHUB_PREVIEW[selectedFindingId] ?? 'Custom fix for this finding.'}
                        </p>
                        <p className="text-[11px] text-muted">
                          The PR will <strong>not</strong> auto-merge. A human must review and merge it manually.
                        </p>
                      </div>
                    )}
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => {
                        if (remediationMode === 'aws') {
                          void handleAwsRemediate('detach');
                        } else {
                          void handleGithubRemediate();
                        }
                      }}
                      disabled={remediationLoading}
                      className="flex-1 rounded bg-accent px-3 py-2 font-mono text-xs font-semibold text-[#0A0E14] transition-opacity hover:opacity-90 disabled:opacity-40"
                    >
                      {remediationLoading
                        ? 'APPLYING...'
                        : remediationMode === 'aws'
                          ? 'CONFIRM & DETACH'
                          : 'CONFIRM & OPEN PR'}
                    </button>
                    <button
                      onClick={() => {
                        setRemediationMode(null);
                        setRemediationResult(null);
                        setRemediationLogs([]);
                        setActiveRemediationAction(null);
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
              {activeRemediationAction && (remediationLoading || remediationResult) && (
                <div className="mb-3">
                  <div className="text-[10px] font-mono font-semibold uppercase tracking-wider text-muted mb-1.5">
                    {activeRemediationAction === 'aws' ? 'AWS Remediation Log' : 'GitHub Remediation Log'}
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
                    {remediationLoading && <span className="cursor-blink" />}
                  </div>
                </div>
              )}

              {/* Result state */}
              {remediationResult && (
                <div className="space-y-3">
                  <div
                    className={`rounded border px-3 py-2 ${
                      remediationResult.type === 'success'
                        ? 'border-low/40 bg-low/10'
                        : 'border-critical/40 bg-critical/10'
                    }`}
                  >
                    <div
                      className={`text-xs font-mono font-semibold ${
                        remediationResult.type === 'success' ? 'text-low' : 'text-critical'
                      }`}
                    >
                      {remediationResult.type === 'success' ? 'SUCCESS' : 'ERROR'}
                    </div>
                    <p className="text-xs text-foreground/90 mt-1">{remediationResult.message}</p>
                    {remediationResult.prUrl && (
                      <a
                        href={remediationResult.prUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-accent underline hover:opacity-80 mt-1 inline-block"
                      >
                        {remediationResult.prUrl}
                      </a>
                    )}
                  </div>

                  <div className="flex gap-2">
                    {remediationResult.undoable && (
                      <button
                        onClick={() => handleAwsRemediate('reattach')}
                        disabled={remediationLoading}
                        className="flex-1 rounded border border-accent/40 bg-accent/10 px-3 py-2 font-mono text-xs font-semibold text-accent transition-opacity hover:opacity-80 disabled:opacity-40"
                      >
                        {remediationLoading ? 'APPLYING...' : 'UNDO -- RE-ATTACH POLICY'}
                      </button>
                    )}
                    <button
                      onClick={() => {
                        setRemediationMode(null);
                        setRemediationResult(null);
                        setRemediationLogs([]);
                        setActiveRemediationAction(null);
                      }}
                      className="rounded border border-border-hairline bg-panel px-3 py-2 font-mono text-xs text-muted transition-opacity hover:opacity-80"
                    >
                      DISMISS
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
