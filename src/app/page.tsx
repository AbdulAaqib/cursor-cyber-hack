'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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

const NODE_POSITIONS: Record<string, { x: number; y: number }> = {
  'lambda-log-processor': { x: 100, y: 300 },
  'ci-deploy-bot': { x: 100, y: 100 },
  'data-processor-role': { x: 400, y: 300 },
  'readonly-analytics-role': { x: 400, y: 100 },
  'admin-deploy-role': { x: 700, y: 300 },
  AdministratorAccess: { x: 1000, y: 300 },
};

const SENSITIVITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  UNKNOWN: '#9ca3af',
};

function CustomNode({ data }: { data: { label: string; sensitivity?: string; visited?: boolean } }) {
  const color = data.visited ? SENSITIVITY_COLORS[data.sensitivity ?? 'UNKNOWN'] : '#9ca3af';
  return (
    <div
      className="rounded-md border-2 px-4 py-2 text-sm font-medium shadow-sm transition-colors duration-500"
      style={{
        borderColor: color,
        backgroundColor: data.visited ? '#ffffff' : '#f3f4f6',
        color: data.visited ? '#111827' : '#6b7280',
      }}
    >
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div>{data.label}</div>
      {data.visited && data.sensitivity && (
        <div className="text-xs mt-1 font-semibold" style={{ color }}>
          {data.sensitivity}
        </div>
      )}
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = { custom: CustomNode };

export default function Home() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string>('');
  const [investigating, setInvestigating] = useState(false);
  const [reasoning, setReasoning] = useState('');
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [visitedNodes, setVisitedNodes] = useState<Set<string>>(new Set());
  const [knownEdges, setKnownEdges] = useState<Set<string>>(new Set());
  const [nodeSensitivities, setNodeSensitivities] = useState<Record<string, string>>({});
  const reasoningRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch('/api/findings')
      .then((r) => r.json())
      .then((data) => {
        setFindings(data);
        if (data.length > 0) setSelectedFindingId(data[0].id);
      });
  }, []);

  useEffect(() => {
    if (reasoningRef.current) {
      reasoningRef.current.scrollTop = reasoningRef.current.scrollHeight;
    }
  }, [reasoning]);

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
      },
    }));
  }, [visitedNodes, nodeSensitivities]);

  const edges: Edge[] = useMemo(() => {
    const baseEdges = [
      { id: 'e1', source: 'lambda-log-processor', target: 'data-processor-role', label: 'AssumeRole' },
      { id: 'e2', source: 'data-processor-role', target: 'admin-deploy-role', label: 'PassRole' },
      { id: 'e3', source: 'admin-deploy-role', target: 'AdministratorAccess', label: 'AttachRolePolicy' },
      { id: 'e4', source: 'ci-deploy-bot', target: 'readonly-analytics-role', label: 'AssumeRole' },
    ];
    return baseEdges.map((e) => ({
      ...e,
      animated: knownEdges.has(e.id),
      style: {
        stroke: knownEdges.has(e.id) ? '#111827' : '#d1d5db',
        strokeWidth: knownEdges.has(e.id) ? 2 : 1,
        transition: 'all 0.5s',
      },
      labelStyle: {
        fill: knownEdges.has(e.id) ? '#111827' : '#9ca3af',
        fontSize: 12,
        fontWeight: knownEdges.has(e.id) ? 600 : 400,
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: knownEdges.has(e.id) ? '#111827' : '#d1d5db',
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
          }
        } catch {
          // ignore parse errors
        }
      }
    }

    setInvestigating(false);
  }, [selectedFindingId]);

  const severityColor = useMemo(() => {
    if (!verdict) return '';
    const map: Record<string, string> = {
      CRITICAL: 'bg-red-100 border-red-400 text-red-900',
      HIGH: 'bg-orange-100 border-orange-400 text-orange-900',
      MEDIUM: 'bg-yellow-100 border-yellow-400 text-yellow-900',
      LOW: 'bg-gray-100 border-gray-400 text-gray-900',
    };
    return map[verdict.severity] ?? '';
  }, [verdict]);

  return (
    <div className="flex flex-col h-screen">
      <header className="bg-slate-900 text-white px-6 py-4">
        <h1 className="text-lg font-bold">Exposure Reasoning Agent</h1>
        <p className="text-xs text-slate-300 mt-1">
          The average enterprise employee holds ~96,000 permissions — no human traces reachability at that scale manually.
        </p>
      </header>

      <main className="flex-1 flex overflow-hidden">
        <aside className="w-96 flex flex-col border-r border-gray-200 bg-white">
          <div className="p-4 border-b border-gray-200 space-y-3">
            <label className="block text-sm font-medium text-gray-700">Select Finding</label>
            <select
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm"
              value={selectedFindingId}
              onChange={(e) => setSelectedFindingId(e.target.value)}
              disabled={investigating}
            >
              {findings.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.id} — {f.package} (CVSS {f.cvss})
                </option>
              ))}
            </select>
            <button
              onClick={handleInvestigate}
              disabled={investigating || !selectedFindingId}
              className="w-full rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
            >
              {investigating ? 'Investigating…' : 'Investigate'}
            </button>
          </div>

          <div className="flex-1 flex flex-col min-h-0">
            <div className="px-4 py-2 text-xs font-semibold uppercase tracking-wider text-gray-500 border-b border-gray-200">
              Agent Reasoning
            </div>
            <div
              ref={reasoningRef}
              className="flex-1 overflow-auto p-4 text-sm text-gray-800 whitespace-pre-wrap"
            >
              {reasoning || (
                <span className="text-gray-400 italic">
                  Reasoning will appear here as the agent explores the graph…
                </span>
              )}
            </div>
          </div>

          {verdict && (
            <div className={`border-t-2 p-4 ${severityColor}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold uppercase tracking-wider">Verdict</span>
                <span className="rounded px-2 py-1 text-xs font-bold border bg-white">
                  {verdict.severity}
                </span>
              </div>
              <p className="text-sm font-medium mb-2">{verdict.pathSummary}</p>

              <div className={`mb-3 inline-flex items-center gap-2 rounded px-2 py-1 text-xs font-semibold border ${verdict.codeReachable ? 'bg-orange-50 border-orange-300 text-orange-800' : 'bg-gray-50 border-gray-300 text-gray-600'}`}>
                <span>Code path:</span>
                <span>{verdict.codeReachable ? 'REACHABLE' : 'NOT REACHABLE'}</span>
                <span className="font-normal">— {verdict.codeReachabilityReason}</span>
              </div>

              <div className="space-y-2">
                <div>
                  <div className="text-xs font-semibold uppercase text-opacity-80 mb-1">Hops</div>
                  <ul className="space-y-1">
                    {verdict.hops.map((h, i) => (
                      <li key={i} className="text-xs">
                        <span className="font-semibold">{h.from}</span> →{' '}
                        <span className="font-semibold">{h.to}</span>{' '}
                        <span className="text-gray-600">({h.event})</span>{' '}
                        {h.risky ? (
                          <span className="text-red-600 font-semibold">risky</span>
                        ) : (
                          <span className="text-green-600">safe</span>
                        )}
                        <div className="text-gray-500">{h.reason}</div>
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <div className="text-xs font-semibold uppercase text-opacity-80 mb-1">Counterfactual</div>
                  <p className="text-xs">{verdict.counterfactual}</p>
                </div>
                <div>
                  <div className="text-xs font-semibold uppercase text-opacity-80 mb-1">Recommendation</div>
                  <p className="text-xs">{verdict.recommendation}</p>
                </div>
              </div>
            </div>
          )}
        </aside>

        <div className="flex-1 bg-slate-50">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            attributionPosition="bottom-left"
          >
            <Background gap={16} size={1} color="#e2e8f0" />
            <Controls />
          </ReactFlow>
        </div>
      </main>

      <footer className="bg-white border-t border-gray-200 px-6 py-2 text-xs text-gray-500">
        Lightweight, agent-driven alternative to attack-path-analysis platforms like Wiz/Orca — built to run in minutes with zero infrastructure.
      </footer>
    </div>
  );
}
