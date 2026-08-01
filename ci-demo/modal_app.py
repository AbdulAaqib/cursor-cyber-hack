"""
CI/CD integration for the Exposure Reasoning Agent.

Deployed on Modal as a serverless container. A CI pipeline (see
../.github/workflows/exposure-scan.yml) calls this endpoint the moment a new
finding shows up — this container fetches the finding, calls the already-deployed
agent (Next.js + Vercel AI SDK, running at VERCEL_URL below), and returns a
structured verdict the pipeline can post back into the PR. This is the "trigger"
and "prioritization output" steps of the pipeline made real: no manual step,
no separate dashboard to check.

Deploy: modal deploy ci-demo/modal_app.py
"""

import json

import modal

app = modal.App("exposure-reasoning-ci")

image = modal.Image.debian_slim(python_version="3.12").pip_install(
    "httpx", "fastapi[standard]"
)

VERCEL_URL = "https://cursor-cyber-hack.vercel.app/api/investigate"


@app.function(image=image, timeout=120)
@modal.fastapi_endpoint(method="POST")
def scan(item: dict):
    """Trigger an investigation and return the structured verdict.

    Body: {"findingId": "SNYK-2026-001"}
    """
    import httpx

    finding_id = item.get("findingId", "SNYK-2026-001")

    verdict = None
    with httpx.Client(timeout=100) as client:
        with client.stream(
            "POST", VERCEL_URL, json={"findingId": finding_id}
        ) as response:
            for line in response.iter_lines():
                if not line.startswith("data: "):
                    continue
                try:
                    payload = json.loads(line[len("data: "):])
                except json.JSONDecodeError:
                    continue
                if payload.get("type") == "verdict":
                    verdict = payload.get("data")

    if verdict is None:
        return {"error": f"No verdict produced for {finding_id}"}

    return {"findingId": finding_id, "verdict": verdict}
