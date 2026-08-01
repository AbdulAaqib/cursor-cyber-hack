const GITHUB_API_BASE = 'https://api.github.com';
const REPO = process.env.GITHUB_REPO!;
const TOKEN = process.env.GITHUB_TOKEN!;

const SNYK_2026_001_PATH = 'web/src/demo-repo/lambda-log-processor/processor.ts';
const SNYK_2026_001_CONTENT = `import { parseLogEntry } from 'log-utils-lite';

// Processes raw log bodies from the Lambda event. Called for every invocation.
export function processLogs(rawBodies: string[]) {
  return rawBodies.map((body) => {
    if (typeof body !== 'string' || body.length > 1_000_000) {
      throw new Error('Invalid log entry: must be a string under 1MB');
    }
    return parseLogEntry(body);
  });
}
`;

const SNYK_2026_002_PATH = 'web/src/demo-repo/ci-deploy-bot/deploy-utils.ts';
const SNYK_2026_002_CONTENT = `// padString was imported for potential future CLI formatting use (see TICKET-1183)
// but is NOT currently called anywhere in the active code path.
// Removed dead import to eliminate attack surface from the vulnerable package.
export function formatCliOutput(input: string) {
  // padString(input, 20) -- disabled, see TICKET-1183
  return input.trim();
}
`;

const SNYK_2026_003_PATH = 'web/src/demo-repo/api-gateway-service/fetcher.ts';
const SNYK_2026_003_CONTENT = `const BLOCKED_HOSTS = ['169.254.169.254', 'metadata.google.internal'];

function isBlockedUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      BLOCKED_HOSTS.includes(parsed.hostname) ||
      parsed.hostname.startsWith('169.254.') ||
      parsed.hostname === 'localhost' ||
      parsed.hostname.startsWith('127.') ||
      parsed.hostname.startsWith('10.') ||
      parsed.hostname.startsWith('192.168.')
    );
  } catch {
    return true; // reject unparseable URLs rather than risk it
  }
}

export async function fetchExternal(url: string): Promise<string> {
  if (isBlockedUrl(url)) {
    throw new Error('Requests to internal/link-local addresses are not allowed');
  }
  const res = await fetch(url);
  return res.text();
}
`;

const FIXES: Record<
  string,
  { path: string; content: string; description: string }
> = {
  'SNYK-2026-001': {
    path: SNYK_2026_001_PATH,
    content: SNYK_2026_001_CONTENT,
    description:
      'Add input validation to `processLogs` before calling `parseLogEntry` — rejects non-string entries and entries exceeding 1MB to prevent malformed input from reaching the vulnerable parser.',
  },
  'SNYK-2026-002': {
    path: SNYK_2026_002_PATH,
    content: SNYK_2026_002_CONTENT,
    description:
      'Remove the dead `padString` import from `string-pad-utility` entirely. The function is not called in the active code path, so the import is pure attack surface.',
  },
  'SNYK-2026-003': {
    path: SNYK_2026_003_PATH,
    content: SNYK_2026_003_CONTENT,
    description:
      'Add URL validation to `fetchExternal` that rejects requests to internal/link-local IP ranges (particularly 169.254.169.254, the cloud instance metadata service) before fetching.',
  },
};

function githubHeaders() {
  return {
    Authorization: `Bearer ${TOKEN}`,
    Accept: 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

async function githubFetch(path: string, init?: RequestInit) {
  const url = `${GITHUB_API_BASE}/repos/${REPO}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: { ...githubHeaders(), ...(init?.headers ?? {}) },
  });
  return res;
}

export interface RemediationResult {
  prUrl: string;
  branchName: string;
}

function shortSha(sha: string): string {
  return sha.slice(0, 7);
}

export async function openFixPr(
  findingId: string,
  onLog?: (line: string) => void,
): Promise<RemediationResult> {
  const log = (line: string) => {
    if (onLog) onLog(line);
  };

  const fix = FIXES[findingId];
  if (!fix) {
    throw new Error(`No fix defined for finding ${findingId}`);
  }

  // 1. Get main's current commit SHA
  log(`Fetching main ref...`);
  const refRes = await githubFetch('/git/ref/heads/main');
  if (!refRes.ok) {
    throw new Error(
      `Failed to fetch main ref: ${refRes.status} ${await refRes.text()}`,
    );
  }
  const refData = (await refRes.json()) as { object: { sha: string } };
  const mainSha = refData.object.sha;
  log(`Done: main is at commit ${shortSha(mainSha)}`);

  // 2. Create new branch
  const branchName = `fix/${findingId}-remediation-${Date.now()}`;
  log(`Creating branch ${branchName}...`);
  const createRefRes = await githubFetch('/git/refs', {
    method: 'POST',
    body: JSON.stringify({
      ref: `refs/heads/${branchName}`,
      sha: mainSha,
    }),
  });
  if (!createRefRes.ok) {
    throw new Error(
      `Failed to create branch ${branchName}: ${createRefRes.status} ${await createRefRes.text()}`,
    );
  }
  log(`Done: created branch ${branchName}`);

  // 3. Get current file blob SHA on the new branch
  log(`Fetching file blob for ${fix.path} on ${branchName}...`);
  const contentsRes = await githubFetch(
    `/contents/${encodeURIComponent(fix.path)}?ref=${encodeURIComponent(branchName)}`,
  );
  if (!contentsRes.ok) {
    throw new Error(
      `Failed to fetch file contents for ${fix.path} on ${branchName}: ${contentsRes.status} ${await contentsRes.text()}\nBranch ${branchName} was created and may be orphaned — clean up manually if needed.`,
    );
  }
  const contentsData = (await contentsRes.json()) as { sha: string };
  const fileSha = contentsData.sha;
  log(`Done: found file blob ${shortSha(fileSha)}`);

  // 4. Update file on the new branch
  log(`Committing fix to ${fix.path} on ${branchName}...`);
  const updateRes = await githubFetch(
    `/contents/${encodeURIComponent(fix.path)}`,
    {
      method: 'PUT',
      body: JSON.stringify({
        message: `fix(${findingId}): ${fix.description}`,
        content: Buffer.from(fix.content).toString('base64'),
        sha: fileSha,
        branch: branchName,
      }),
    },
  );
  if (!updateRes.ok) {
    throw new Error(
      `Failed to update ${fix.path} on ${branchName}: ${updateRes.status} ${await updateRes.text()}\nBranch ${branchName} was created and may be orphaned — clean up manually if needed.`,
    );
  }
  const updateData = (await updateRes.json()) as { content: { sha: string } };
  const newBlobSha = updateData.content.sha;
  log(`Done: committed fix (new blob ${shortSha(newBlobSha)})`);

  // 5. Open PR
  log(`Opening pull request from ${branchName} to main...`);
  const title = `fix(${findingId}): automated remediation — ${fix.description}`;
  const body = `This PR was opened by the **Lighthouse** after explicit human approval.

- **Finding:** ${findingId}
- **Fix:** ${fix.description}

> ⚠️ This PR does **not** auto-merge. A human must review and merge it manually.`;

  const prRes = await githubFetch('/pulls', {
    method: 'POST',
    body: JSON.stringify({
      title,
      head: branchName,
      base: 'main',
      body,
    }),
  });
  if (!prRes.ok) {
    throw new Error(
      `Failed to create PR from ${branchName} to main: ${prRes.status} ${await prRes.text()}\nBranch ${branchName} exists with the fix commit — you can open a PR manually if needed.`,
    );
  }
  const prData = (await prRes.json()) as { number: number; html_url: string };
  log(`Done: opened PR #${prData.number}: ${prData.html_url}`);

  return { prUrl: prData.html_url, branchName };
}
