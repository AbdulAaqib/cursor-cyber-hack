const GITHUB_API_BASE = 'https://api.github.com';

interface GithubRun {
  id: number;
  status: string;
  conclusion: string | null;
  head_branch: string;
  event: string;
  display_title: string;
  created_at: string;
  html_url: string;
  run_number: number;
}

export async function GET() {
  const repo = process.env.GITHUB_REPO;
  const token = process.env.GITHUB_TOKEN;

  if (!repo || !token) {
    return Response.json(
      { error: 'GITHUB_REPO/GITHUB_TOKEN not configured' },
      { status: 400 },
    );
  }

  const res = await fetch(
    `${GITHUB_API_BASE}/repos/${repo}/actions/runs?per_page=10`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      // Never cache CI status — it's meant to be live.
      cache: 'no-store',
    },
  );

  if (!res.ok) {
    return Response.json(
      { error: `GitHub API error: ${res.status}` },
      { status: 502 },
    );
  }

  const data = (await res.json()) as { workflow_runs: GithubRun[] };

  return Response.json({
    repo,
    runs: data.workflow_runs.map((r) => ({
      id: r.id,
      runNumber: r.run_number,
      status: r.status,
      conclusion: r.conclusion,
      branch: r.head_branch,
      event: r.event,
      title: r.display_title,
      createdAt: r.created_at,
      htmlUrl: r.html_url,
    })),
  });
}
