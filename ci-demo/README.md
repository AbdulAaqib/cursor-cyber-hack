# CI/CD integration example

Demonstrates the "trigger → agent reasons → verdict pushed into the existing workflow" step from the real-world integration pipeline — actually wired up, not just narrated.

```
PR opened (GitHub Actions)
   → curls the Modal-hosted endpoint (modal_app.py)
   → Modal calls the deployed agent (Vercel, /api/investigate)
   → agent traces code reachability + real AWS IAM blast-radius
   → verdict posted as a PR comment
```

- **`modal_app.py`** — a Modal serverless function (`https://abdulaaqib2--exposure-reasoning-ci-scan.modal.run`) that proxies to the already-deployed Next.js agent and returns a structured verdict. Modal does the CI/CD compute step here; it doesn't reimplement the agent, it calls it.
- **`../.github/workflows/exposure-scan.yml`** — runs on every PR, investigates both demo findings, posts the results as a PR comment.

Redeploy after changing `modal_app.py`: `modal deploy ci-demo/modal_app.py`
