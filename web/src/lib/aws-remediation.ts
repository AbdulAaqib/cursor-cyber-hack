import {
  IAMClient,
  DetachRolePolicyCommand,
  AttachRolePolicyCommand,
  ListAttachedRolePoliciesCommand,
} from '@aws-sdk/client-iam';

export const AWS_REMEDIATION_TARGETS: Record<
  string,
  { roleName: string; policyArn: string; policyLabel: string }
> = {
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

function client() {
  return new IAMClient({
    region: process.env.AWS_REGION ?? 'us-east-1',
    credentials: {
      accessKeyId: process.env.AWS_REMEDIATION_ACCESS_KEY_ID!,
      secretAccessKey: process.env.AWS_REMEDIATION_SECRET_ACCESS_KEY!,
    },
  });
}

async function isPolicyAttached(roleName: string, policyArn: string): Promise<boolean> {
  const result = await client().send(
    new ListAttachedRolePoliciesCommand({ RoleName: roleName }),
  );
  const attached = result.AttachedPolicies ?? [];
  return attached.some((p) => p.PolicyArn === policyArn);
}

export interface AwsRemediationResult {
  roleName: string;
  policyArn: string;
  action: 'detached' | 'reattached';
}

export async function detachPolicy(
  findingId: string,
  onLog?: (line: string) => void,
): Promise<AwsRemediationResult> {
  const target = AWS_REMEDIATION_TARGETS[findingId];
  if (!target) {
    throw new Error(`No AWS remediation target defined for finding ${findingId}`);
  }
  const { roleName, policyArn, policyLabel } = target;

  const log = (line: string) => {
    if (onLog) onLog(line);
  };

  log(`Checking current policies on ${roleName}...`);
  const initiallyAttached = await isPolicyAttached(roleName, policyArn);
  log(
    initiallyAttached
      ? `Found: ${policyLabel} attached`
      : `Found: no ${policyLabel} attached`,
  );

  log(`Calling iam:DetachRolePolicy(${roleName}, ${policyLabel})...`);
  await client().send(
    new DetachRolePolicyCommand({ RoleName: roleName, PolicyArn: policyArn }),
  );
  log(`AWS confirmed the API call succeeded.`);

  log(`Verifying new state...`);
  const nowAttached = await isPolicyAttached(roleName, policyArn);
  if (nowAttached) {
    log(`Confirmed: ${policyLabel} is STILL attached — unexpected!`);
    throw new Error(
      `DetachRolePolicy succeeded but ${policyLabel} is still attached to ${roleName}`,
    );
  }
  log(`Confirmed: ${policyLabel} is no longer attached.`);

  return {
    roleName,
    policyArn,
    action: 'detached',
  };
}

export async function reattachPolicy(
  findingId: string,
  onLog?: (line: string) => void,
): Promise<AwsRemediationResult> {
  const target = AWS_REMEDIATION_TARGETS[findingId];
  if (!target) {
    throw new Error(`No AWS remediation target defined for finding ${findingId}`);
  }
  const { roleName, policyArn, policyLabel } = target;

  const log = (line: string) => {
    if (onLog) onLog(line);
  };

  log(`Checking current policies on ${roleName}...`);
  const initiallyAttached = await isPolicyAttached(roleName, policyArn);
  log(
    initiallyAttached
      ? `Found: ${policyLabel} already attached`
      : `Found: no ${policyLabel} attached`,
  );

  log(`Calling iam:AttachRolePolicy(${roleName}, ${policyLabel})...`);
  await client().send(
    new AttachRolePolicyCommand({ RoleName: roleName, PolicyArn: policyArn }),
  );
  log(`AWS confirmed the API call succeeded.`);

  log(`Verifying new state...`);
  const nowAttached = await isPolicyAttached(roleName, policyArn);
  if (!nowAttached) {
    log(`Confirmed: ${policyLabel} is NOT attached — unexpected!`);
    throw new Error(
      `AttachRolePolicy succeeded but ${policyLabel} is not attached to ${roleName}`,
    );
  }
  log(`Confirmed: ${policyLabel} is attached.`);

  return {
    roleName,
    policyArn,
    action: 'reattached',
  };
}
