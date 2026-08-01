import {
  IAMClient,
  DetachRolePolicyCommand,
  AttachRolePolicyCommand,
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

export async function detachAdminPolicy() {
  await client().send(
    new DetachRolePolicyCommand({ RoleName: ROLE_NAME, PolicyArn: POLICY_ARN }),
  );
  return {
    roleName: ROLE_NAME,
    policyArn: POLICY_ARN,
    action: 'detached' as const,
  };
}

export async function reattachAdminPolicy() {
  await client().send(
    new AttachRolePolicyCommand({ RoleName: ROLE_NAME, PolicyArn: POLICY_ARN }),
  );
  return {
    roleName: ROLE_NAME,
    policyArn: POLICY_ARN,
    action: 'reattached' as const,
  };
}
