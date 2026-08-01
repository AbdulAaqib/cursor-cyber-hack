import {
  IAMClient,
  DetachRolePolicyCommand,
  AttachRolePolicyCommand,
  ListAttachedRolePoliciesCommand,
} from '@aws-sdk/client-iam';

const ROLE_NAME = 'admin-deploy-role';
const POLICY_ARN = 'arn:aws:iam::aws:policy/AdministratorAccess';

function client() {
  return new IAMClient({
    region: process.env.AWS_REGION ?? 'us-east-1',
    credentials: {
      accessKeyId: process.env.AWS_REMEDIATION_ACCESS_KEY_ID!,
      secretAccessKey: process.env.AWS_REMEDIATION_SECRET_ACCESS_KEY!,
    },
  });
}

async function isPolicyAttached(): Promise<boolean> {
  const result = await client().send(
    new ListAttachedRolePoliciesCommand({ RoleName: ROLE_NAME }),
  );
  const attached = result.AttachedPolicies ?? [];
  return attached.some((p) => p.PolicyArn === POLICY_ARN);
}

export interface AwsRemediationResult {
  roleName: string;
  policyArn: string;
  action: 'detached' | 'reattached';
}

export async function detachAdminPolicy(
  onLog?: (line: string) => void,
): Promise<AwsRemediationResult> {
  const log = (line: string) => {
    if (onLog) onLog(line);
  };

  log(`Checking current policies on ${ROLE_NAME}...`);
  const initiallyAttached = await isPolicyAttached();
  log(
    initiallyAttached
      ? `Found: AdministratorAccess attached`
      : `Found: no AdministratorAccess attached`,
  );

  log(`Calling iam:DetachRolePolicy(${ROLE_NAME}, AdministratorAccess)...`);
  await client().send(
    new DetachRolePolicyCommand({ RoleName: ROLE_NAME, PolicyArn: POLICY_ARN }),
  );
  log(`AWS confirmed the API call succeeded.`);

  log(`Verifying new state...`);
  const nowAttached = await isPolicyAttached();
  if (nowAttached) {
    log(`Confirmed: AdministratorAccess is STILL attached — unexpected!`);
    throw new Error(
      `DetachRolePolicy succeeded but AdministratorAccess is still attached to ${ROLE_NAME}`,
    );
  }
  log(`Confirmed: AdministratorAccess is no longer attached.`);

  return {
    roleName: ROLE_NAME,
    policyArn: POLICY_ARN,
    action: 'detached',
  };
}

export async function reattachAdminPolicy(
  onLog?: (line: string) => void,
): Promise<AwsRemediationResult> {
  const log = (line: string) => {
    if (onLog) onLog(line);
  };

  log(`Checking current policies on ${ROLE_NAME}...`);
  const initiallyAttached = await isPolicyAttached();
  log(
    initiallyAttached
      ? `Found: AdministratorAccess already attached`
      : `Found: no AdministratorAccess attached`,
  );

  log(`Calling iam:AttachRolePolicy(${ROLE_NAME}, AdministratorAccess)...`);
  await client().send(
    new AttachRolePolicyCommand({ RoleName: ROLE_NAME, PolicyArn: POLICY_ARN }),
  );
  log(`AWS confirmed the API call succeeded.`);

  log(`Verifying new state...`);
  const nowAttached = await isPolicyAttached();
  if (!nowAttached) {
    log(`Confirmed: AdministratorAccess is NOT attached — unexpected!`);
    throw new Error(
      `AttachRolePolicy succeeded but AdministratorAccess is not attached to ${ROLE_NAME}`,
    );
  }
  log(`Confirmed: AdministratorAccess is attached.`);

  return {
    roleName: ROLE_NAME,
    policyArn: POLICY_ARN,
    action: 'reattached',
  };
}
