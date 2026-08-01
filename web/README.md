# Exposure Reasoning Agent

An AI agent that fuses Snyk vulnerability findings, code-reachability, and AWS IAM blast-radius into a single holistic severity verdict — instead of ranking by raw CVSS score alone.

```
Snyk finding → code reachability check → AWS IAM blast-radius trace → holistic verdict
```

## Setup

```bash
npm install
cp .env.local.example .env.local
# Add your OpenRouter API key to .env.local
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## Why this matters

41% of AppSec teams name vulnerability prioritization as their #1 challenge; the average enterprise employee holds ~96,000 permissions — no human traces reachability at that scale manually.

## Positioning

This is a lightweight, agent-driven alternative to attack-path-analysis platforms like Wiz/Orca Security — not a claim to have invented the category, but a fast, transparent, zero-infrastructure version of it.

## Demo script

1. **Run finding SNYK-2026-001** — watch it trace to `admin-deploy-role` and escalate to HIGH/CRITICAL, complete with the pending-PR counterfactual.
2. **Run finding SNYK-2026-002** — watch it get correctly ruled LOW despite a scarier CVSS score.
3. **Point out the code-reachability step** — it now runs first in both cases, checking whether the vulnerable function is actually invoked before any IAM tracing begins.

## Live AWS mode (optional)

By default the agent uses a mock IAM dataset (`src/data/iam-events.json`). To trace your **real** AWS account instead:

1. Uncomment the AWS variables in `.env.local` and set `USE_LIVE_AWS=true`.
2. Provide read-only IAM credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`).
3. Re-start `npm run dev`.

If live AWS is unreachable (missing credentials, permission denied, etc.) the server automatically falls back to the mock dataset and logs a warning.

> **Note:** Once you switch to live AWS, update `src/data/findings.json` so that `affectedNode` values match actual role names in your account. This is a manual step — the mock findings won't align with real role names.
