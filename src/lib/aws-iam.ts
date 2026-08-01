import {
  IAMClient,
  ListRolesCommand,
  GetRoleCommand,
  ListAttachedRolePoliciesCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand,
  NoSuchEntityException,
} from '@aws-sdk/client-iam';

export class LiveAwsUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LiveAwsUnavailableError';
  }
}

export interface LiveIamEdge {
  source: string;
  target: string;
  event: string;
}

export interface LiveSensitivityInfo {
  sensitivity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason: string;
  pendingChange?: string;
}

export interface PolicyDetail {
  policyName: string;
  actions: string[];
  resources: string[];
}

const HIGH_RISK_ACTIONS = ['iam:PassRole', 'iam:*', '*:*', 'sts:AssumeRole'];
const MAX_ROLES = 200;

async function fetchPolicyDocument(
  client: IAMClient,
  policyArn: string,
): Promise<{ Statement?: Array<Record<string, unknown>> } | null> {
  try {
    const policyResult = await client.send(
      new GetPolicyCommand({ PolicyArn: policyArn }),
    );
    const defaultVersionId = policyResult.Policy?.DefaultVersionId;
    if (!defaultVersionId) return null;

    const versionResult = await client.send(
      new GetPolicyVersionCommand({
        PolicyArn: policyArn,
        VersionId: defaultVersionId,
      }),
    );

    const doc = versionResult.PolicyVersion?.Document;
    if (!doc) return null;

    let parsedDoc: { Statement?: Array<Record<string, unknown>> } | null = null;
    try {
      parsedDoc =
        typeof doc === 'string'
          ? JSON.parse(decodeURIComponent(doc))
          : (doc as { Statement?: Array<Record<string, unknown>> });
    } catch {
      return null;
    }
    return parsedDoc;
  } catch {
    return null;
  }
}

export async function getAttachedPolicyDetails(
  roleName: string,
): Promise<PolicyDetail[]> {
  try {
    const client = new IAMClient({
      region: process.env.AWS_REGION ?? 'us-east-1',
    });

    const attachedResult = await client.send(
      new ListAttachedRolePoliciesCommand({ RoleName: roleName }),
    );
    const attachedPolicies = attachedResult.AttachedPolicies ?? [];

    const details: PolicyDetail[] = [];
    for (const attached of attachedPolicies) {
      const policyName = attached.PolicyName ?? 'unknown-policy';
      const policyArn = attached.PolicyArn;
      if (!policyArn) {
        details.push({ policyName, actions: [], resources: [] });
        continue;
      }

      const parsedDoc = await fetchPolicyDocument(client, policyArn);
      if (!parsedDoc) {
        details.push({ policyName, actions: [], resources: [] });
        continue;
      }

      const actions: string[] = [];
      const resources: string[] = [];
      for (const statement of parsedDoc.Statement ?? []) {
        if (statement.Effect !== 'Allow') continue;
        const stmtActions = statement.Action;
        const stmtResources = statement.Resource;

        if (typeof stmtActions === 'string') actions.push(stmtActions);
        else if (Array.isArray(stmtActions)) actions.push(...stmtActions);

        if (typeof stmtResources === 'string') resources.push(stmtResources);
        else if (Array.isArray(stmtResources)) resources.push(...stmtResources);
      }
      details.push({ policyName, actions, resources });
    }

    return details;
  } catch (err) {
    if (err instanceof NoSuchEntityException) {
      return [];
    }
    const message = err instanceof Error ? err.message : String(err);
    throw new LiveAwsUnavailableError(
      `Failed to fetch attached policy details for ${roleName}: ${message}`,
    );
  }
}

export async function buildLiveIamGraph(): Promise<{
  edges: LiveIamEdge[];
  sensitivity: Record<string, LiveSensitivityInfo>;
}> {
  try {
    const client = new IAMClient({
      region: process.env.AWS_REGION ?? 'us-east-1',
    });

    const edges: LiveIamEdge[] = [];
    const sensitivity: Record<string, LiveSensitivityInfo> = {};

    // --- 1. List roles (paginated, cap at MAX_ROLES) ---
    const roles: { RoleName: string; Arn: string; AssumeRolePolicyDocument?: string }[] = [];
    let marker: string | undefined;
    do {
      const listResult = await client.send(
        new ListRolesCommand({ Marker: marker, MaxItems: 100 }),
      );
      for (const role of listResult.Roles ?? []) {
        if (role.RoleName && role.Arn) {
          roles.push({
            RoleName: role.RoleName,
            Arn: role.Arn,
            AssumeRolePolicyDocument: role.AssumeRolePolicyDocument,
          });
        }
        if (roles.length >= MAX_ROLES) break;
      }
      marker = listResult.IsTruncated ? listResult.Marker : undefined;
    } while (marker && roles.length < MAX_ROLES);

    // --- 2. Build trust edges from AssumeRolePolicyDocument ---
    for (const role of roles) {
      const roleName = role.RoleName;

      // Default sensitivity for the role
      if (!sensitivity[roleName]) {
        sensitivity[roleName] = {
          sensitivity: 'MEDIUM',
          reason: `IAM role ${roleName}`,
        };
      }

      // GetRole to fetch the AssumeRolePolicyDocument if not present in ListRoles
      let policyDoc = role.AssumeRolePolicyDocument;
      if (!policyDoc) {
        try {
          const getRoleResult = await client.send(
            new GetRoleCommand({ RoleName: roleName }),
          );
          policyDoc = getRoleResult.Role?.AssumeRolePolicyDocument;
        } catch {
          // If we can't fetch the role details, skip trust graph for this role
          continue;
        }
      }

      if (!policyDoc) continue;

      let parsedPolicy: { Statement?: Array<Record<string, unknown>> } | null = null;
      try {
        parsedPolicy = JSON.parse(decodeURIComponent(policyDoc));
      } catch {
        continue;
      }

      for (const statement of parsedPolicy?.Statement ?? []) {
        if (statement.Effect !== 'Allow') continue;

        const principals: string[] = [];
        const principal = statement.Principal as Record<string, string | string[]> | undefined;
        if (principal) {
          if (typeof principal.AWS === 'string') principals.push(principal.AWS);
          else if (Array.isArray(principal.AWS)) principals.push(...principal.AWS);
          if (typeof principal.Service === 'string') principals.push(principal.Service);
          else if (Array.isArray(principal.Service)) principals.push(...principal.Service);
        }

        for (const p of principals) {
          let sourceName: string;
          if (p.startsWith('arn:aws:iam::')) {
            // Extract role name from ARN (arn:aws:iam::<account>:role/<roleName>)
            const parts = p.split('/');
            sourceName = parts[parts.length - 1] || p;
          } else if (p.includes('.amazonaws.com')) {
            sourceName = p;
          } else {
            sourceName = p;
          }

          edges.push({ source: sourceName, target: roleName, event: 'AssumeRole' });

          // Add sensitivity for source principal if not already present
          if (!sensitivity[sourceName]) {
            const isReadOnly =
              /ReadOnly|Viewer|Analyst/i.test(sourceName);
            sensitivity[sourceName] = {
              sensitivity: isReadOnly ? 'LOW' : 'MEDIUM',
              reason: isReadOnly
                ? `Read-only principal ${sourceName}`
                : `Principal ${sourceName}`,
            };
          }
        }
      }
    }

    // --- 3. Scan attached policies ---
    for (const role of roles) {
      const roleName = role.RoleName;
      let attachedPolicies: { PolicyName?: string; PolicyArn?: string }[] = [];
      try {
        const attachedResult = await client.send(
          new ListAttachedRolePoliciesCommand({ RoleName: roleName }),
        );
        attachedPolicies = attachedResult.AttachedPolicies ?? [];
      } catch {
        continue;
      }

      for (const attached of attachedPolicies) {
        const policyName = attached.PolicyName ?? 'unknown-policy';
        const policyArn = attached.PolicyArn;

        // Admin / PowerUser heuristic
        const isAdminLike =
          /AdministratorAccess|Admin|PowerUser/i.test(policyName);

        edges.push({
          source: roleName,
          target: policyName,
          event: 'AttachRolePolicy',
        });

        if (isAdminLike) {
          sensitivity[policyName] = {
            sensitivity: 'CRITICAL',
            reason: `Admin-tier managed policy ${policyName} attached to ${roleName}`,
          };
          sensitivity[roleName] = {
            sensitivity: 'CRITICAL',
            reason: `Has admin-tier policy ${policyName} attached`,
          };
          continue;
        }

        // Default sensitivity for non-admin policy
        if (!sensitivity[policyName]) {
          sensitivity[policyName] = {
            sensitivity: 'MEDIUM',
            reason: `Managed policy ${policyName}`,
          };
        }

        // --- 4. Optional deep scan for high-risk actions in policy document ---
        if (!policyArn) continue;
        const parsedDoc = await fetchPolicyDocument(client, policyArn);
        if (!parsedDoc) continue;

        let hasHighRisk = false;
        for (const statement of parsedDoc.Statement ?? []) {
          if (statement.Effect !== 'Allow') continue;
          const actions = statement.Action;
          const resources = statement.Resource;
          const actionList: string[] = [];
          if (typeof actions === 'string') actionList.push(actions);
          else if (Array.isArray(actions)) actionList.push(...actions);

          const isBroadResource =
            resources === '*' ||
            (Array.isArray(resources) && resources.includes('*'));

          for (const action of actionList) {
            if (
              HIGH_RISK_ACTIONS.some(
                (hr) => action === hr || action.includes(hr),
              ) &&
              isBroadResource
            ) {
              hasHighRisk = true;
              break;
            }
          }
          if (hasHighRisk) break;
        }

        if (hasHighRisk) {
          const syntheticNode = `${roleName}-elevated-access`;
          edges.push({
            source: roleName,
            target: syntheticNode,
            event: 'PassRole',
          });
          sensitivity[syntheticNode] = {
            sensitivity: 'HIGH',
            reason: `Synthetic node: ${roleName} has broad high-risk actions via ${policyName}`,
          };
          if (sensitivity[roleName].sensitivity !== 'CRITICAL') {
            sensitivity[roleName] = {
              sensitivity: 'HIGH',
              reason: `Role ${roleName} has broad high-risk actions via attached policy ${policyName}`,
            };
          }
        }
      }
    }

    return { edges, sensitivity };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new LiveAwsUnavailableError(
      `Failed to fetch live AWS IAM data: ${message}`,
    );
  }
}
