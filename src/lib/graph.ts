import iamEvents from '@/data/iam-events.json';
import resourceSensitivity from '@/data/resource-sensitivity.json';
import {
  buildLiveIamGraph,
  getAttachedPolicyDetails as getLiveAttachedPolicyDetails,
  LiveAwsUnavailableError,
  type PolicyDetail,
} from './aws-iam';

export interface TrustEdge {
  target: string;
  event: string;
}

export interface SensitivityInfo {
  sensitivity: string;
  reason: string;
  pendingChange?: string;
}

const useLiveAws = process.env.USE_LIVE_AWS === 'true';

interface GraphData {
  adjacency: Record<string, TrustEdge[]>;
  sensitivity: Record<string, SensitivityInfo>;
}

let liveGraphCached: GraphData | undefined;
let liveGraphPromise: Promise<GraphData> | undefined;

function buildMockGraph() {
  const adjacency: Record<string, TrustEdge[]> = {};
  for (const ev of iamEvents as { event: string; source: string; target: string }[]) {
    if (!adjacency[ev.source]) adjacency[ev.source] = [];
    adjacency[ev.source].push({ target: ev.target, event: ev.event });
  }
  return {
    adjacency,
    sensitivity: resourceSensitivity as Record<string, SensitivityInfo>,
  };
}

async function ensureGraph(): Promise<GraphData> {
  if (!useLiveAws) {
    return buildMockGraph();
  }

  if (liveGraphCached) {
    return liveGraphCached;
  }

  if (!liveGraphPromise) {
    liveGraphPromise = (async (): Promise<GraphData> => {
      try {
        const { edges, sensitivity } = await buildLiveIamGraph();
        const adjacency: Record<string, TrustEdge[]> = {};
        for (const ev of edges) {
          if (!adjacency[ev.source]) adjacency[ev.source] = [];
          adjacency[ev.source].push({ target: ev.target, event: ev.event });
        }
        const normalizedSensitivity: Record<string, SensitivityInfo> = {};
        for (const [key, val] of Object.entries(sensitivity)) {
          normalizedSensitivity[key] = {
            sensitivity: val.sensitivity,
            reason: val.reason,
            pendingChange: val.pendingChange,
          };
        }
        liveGraphCached = { adjacency, sensitivity: normalizedSensitivity };
        return liveGraphCached;
      } catch (err) {
        const isAwsError = err instanceof LiveAwsUnavailableError;
        const message = err instanceof Error ? err.message : String(err);
        console.warn(
          `[graph] Live AWS IAM fetch failed${isAwsError ? '' : ' (unexpected error)'}, falling back to mock data:`,
          message,
        );
        return buildMockGraph();
      }
    })();
  }

  return liveGraphPromise;
}

export async function getTrustEdges(node: string): Promise<TrustEdge[]> {
  const graph = await ensureGraph();
  return graph.adjacency[node] ?? [];
}

export async function getResourceSensitivity(node: string): Promise<SensitivityInfo> {
  const graph = await ensureGraph();
  const info = graph.sensitivity[node];
  if (info) return info;
  return { sensitivity: 'UNKNOWN', reason: 'No metadata available' };
}

const MOCK_POLICY_DETAILS: Record<string, PolicyDetail[]> = {
  'admin-deploy-role': [
    { policyName: 'AdministratorAccess', actions: ['*'], resources: ['*'] },
  ],
  'readonly-analytics-role': [
    { policyName: 'ReadOnlyAccess', actions: ['*Get*', '*List*', '*Describe*'], resources: ['*'] },
  ],
};

export async function getAttachedPolicyDetails(node: string): Promise<PolicyDetail[]> {
  if (useLiveAws) {
    try {
      return await getLiveAttachedPolicyDetails(node);
    } catch (err) {
      const isAwsError = err instanceof LiveAwsUnavailableError;
      const message = err instanceof Error ? err.message : String(err);
      console.warn(
        `[graph] Live AWS policy details fetch failed${isAwsError ? '' : ' (unexpected error)'}, falling back to mock data:`,
        message,
      );
      return MOCK_POLICY_DETAILS[node] ?? [];
    }
  }
  return MOCK_POLICY_DETAILS[node] ?? [];
}
