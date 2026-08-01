'use client';

import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';

export default function WorkflowsPage() {
  const reduced = useReducedMotion();

  const sectionReveal = {
    hidden: { opacity: 0, y: 16 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: reduced ? 0 : 0.5, ease: 'easeOut' as const },
    },
  };

  return (
    <div className="flex flex-col min-h-[calc(100vh-48px)] bg-background text-foreground font-sans">
      <motion.section
        className="border-b border-border-hairline px-6 py-10"
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.3 }}
        variants={sectionReveal}
      >
        <div className="max-w-4xl mx-auto">
          <h1 className="font-mono text-2xl font-bold tracking-tight mb-2">Workflows</h1>
          <p className="text-muted text-sm">
            Three distinct pipelines — investigation, remediation, and CI/CD — each designed to
            keep the human in the loop.
          </p>
        </div>
      </motion.section>

      {/* Investigation workflow */}
      <motion.section
        className="border-b border-border-hairline px-6 py-10"
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.2 }}
        variants={sectionReveal}
      >
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center gap-3 mb-6">
            <span className="h-2 w-2 rounded-full bg-accent" />
            <h2 className="font-mono text-sm font-semibold tracking-wide">1. Investigation</h2>
          </div>
          <p className="text-sm text-muted mb-6 max-w-2xl">
            Fuses code reachability and AWS IAM blast-radius tracing into a single holistic
            verdict. The agent reads real source files and real IAM policies — never pre-baked
            severity tags.
          </p>

          <div className="rounded border border-border-hairline bg-panel p-5 mb-6 font-mono text-xs text-foreground leading-relaxed">
            <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
              <div className="rounded border border-border-hairline bg-background p-3 text-center">
                <div className="text-accent font-semibold mb-1">Snyk finding</div>
                <div className="text-[10px] text-muted">patient zero</div>
              </div>
              <div className="flex items-center justify-center text-muted">
                <span className="hidden md:inline">&rarr;</span>
                <span className="md:hidden">&darr;</span>
              </div>
              <div className="rounded border border-border-hairline bg-background p-3 text-center">
                <div className="text-accent font-semibold mb-1">Code reachability</div>
                <div className="text-[10px] text-muted">live source trace</div>
              </div>
              <div className="flex items-center justify-center text-muted">
                <span className="hidden md:inline">&rarr;</span>
                <span className="md:hidden">&darr;</span>
              </div>
              <div className="rounded border border-border-hairline bg-background p-3 text-center">
                <div className="text-accent font-semibold mb-1">IAM blast-radius</div>
                <div className="text-[10px] text-muted">real AWS trust graph</div>
              </div>
            </div>
            <div className="flex justify-center my-3">
              <span className="text-muted">&darr;</span>
            </div>
            <div className="rounded border border-border-hairline bg-background p-3 text-center max-w-sm mx-auto">
              <div className="text-critical font-semibold mb-1">Holistic verdict</div>
              <div className="text-[10px] text-muted">severity + attack narrative</div>
            </div>
          </div>

          <Link
            href="/console"
            className="inline-block rounded bg-accent px-4 py-2 font-mono text-xs font-semibold text-[#0A0E14] transition-opacity hover:opacity-90"
          >
            Run an investigation
          </Link>
        </div>
      </motion.section>

      {/* Remediation workflow */}
      <motion.section
        className="border-b border-border-hairline px-6 py-10"
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.2 }}
        variants={sectionReveal}
      >
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center gap-3 mb-6">
            <span className="h-2 w-2 rounded-full bg-high" />
            <h2 className="font-mono text-sm font-semibold tracking-wide">2. Remediation</h2>
          </div>
          <p className="text-sm text-muted mb-6 max-w-2xl">
            The agent proposes fixes, but never executes them unattended. A deliberate two-stage
            human-approval design keeps the operator in control.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="rounded border border-border-hairline bg-panel p-4">
              <div className="text-[11px] font-mono uppercase tracking-wider text-muted mb-3">
                Stage 1: Prepare fix
              </div>
              <p className="text-xs text-foreground/80 mb-3">
                Clicking &ldquo;Prepare&rdquo; reveals the exact change that will be made — no
                surprises. The operator sees the full scope before anything touches production.
              </p>
              <div className="rounded border border-border-hairline bg-background p-2 font-mono text-[10px] text-muted">
                Preview: detach AdministratorAccess from admin-deploy-role
              </div>
            </div>
            <div className="rounded border border-border-hairline bg-panel p-4">
              <div className="text-[11px] font-mono uppercase tracking-wider text-muted mb-3">
                Stage 2: Confirm &amp; Apply
              </div>
              <p className="text-xs text-foreground/80 mb-3">
                A second, distinct click is required to execute. Nothing happens on a single
                click. This boundary is intentional, not a missing feature.
              </p>
              <div className="rounded border border-border-hairline bg-background p-2 font-mono text-[10px] text-muted">
                Confirm &amp; Detach / Confirm &amp; Open PR
              </div>
            </div>
          </div>

          <div className="space-y-3 mb-6">
            <div className="flex items-start gap-3 rounded border border-border-hairline bg-panel p-3">
              <span className="mt-0.5 h-2 w-2 rounded-full bg-critical shrink-0" />
              <div>
                <div className="font-mono text-xs font-semibold text-foreground mb-1">
                  AWS policy detach
                </div>
                <p className="text-xs text-muted">
                  Detaches a policy from a role via the narrowly-scoped remediator credential. An
                  &ldquo;Undo&rdquo; (re-attach) is always available so the demo is repeatable.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3 rounded border border-border-hairline bg-panel p-3">
              <span className="mt-0.5 h-2 w-2 rounded-full bg-accent shrink-0" />
              <div>
                <div className="font-mono text-xs font-semibold text-foreground mb-1">
                  GitHub pull request
                </div>
                <p className="text-xs text-muted">
                  Opens a real PR against this repo via the GitHub REST API directly — no local
                  git/gh CLI dependency. The PR never auto-merges; a human must review and merge
                  it manually. See the repo&apos;s Pull Requests tab for a live example.
                </p>
              </div>
            </div>
          </div>
        </div>
      </motion.section>

      {/* CI/CD workflow */}
      <motion.section
        className="border-b border-border-hairline px-6 py-10"
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.2 }}
        variants={sectionReveal}
      >
        <div className="max-w-4xl mx-auto">
          <div className="flex items-center gap-3 mb-6">
            <span className="h-2 w-2 rounded-full bg-low" />
            <h2 className="font-mono text-sm font-semibold tracking-wide">3. CI/CD</h2>
          </div>
          <p className="text-sm text-muted mb-6 max-w-2xl">
            Commit-driven detection via GitHub Actions + Modal. Detection and remediation are
            deliberately decoupled — CI never auto-remediates.
          </p>

          <div className="rounded border border-border-hairline bg-panel p-5 mb-6 font-mono text-xs text-foreground leading-relaxed">
            <div className="flex flex-col gap-2 max-w-lg">
              <div className="flex items-center gap-3">
                <div className="rounded border border-border-hairline bg-background px-3 py-2">git push</div>
                <span className="text-muted">&rarr;</span>
                <div className="rounded border border-border-hairline bg-background px-3 py-2">
                  GitHub Actions triggers
                </div>
              </div>
              <div className="flex items-center gap-3 pl-16">
                <span className="text-muted">&darr;</span>
              </div>
              <div className="flex items-center gap-3">
                <div className="rounded border border-border-hairline bg-background px-3 py-2">
                  curl &rarr; Modal endpoint
                </div>
                <span className="text-muted">&rarr;</span>
                <div className="rounded border border-border-hairline bg-background px-3 py-2">
                  Modal &rarr; deployed agent
                </div>
              </div>
              <div className="flex items-center gap-3 pl-16">
                <span className="text-muted">&darr;</span>
              </div>
              <div className="rounded border border-border-hairline bg-background px-3 py-2 max-w-sm">
                Verdict posted as PR/commit comment, linking back to the app for human-approved
                remediation
              </div>
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            <a
              href="https://github.com/AbdulAaqib/cursor-cyber-hack/blob/main/.github/workflows/exposure-scan.yml"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-block rounded border border-border-hairline bg-panel px-4 py-2 font-mono text-xs text-foreground transition-opacity hover:opacity-80"
            >
              View exposure-scan.yml
            </a>
            <span className="inline-block rounded border border-border-hairline bg-panel px-4 py-2 font-mono text-xs text-muted">
              Modal dashboard: see your Modal apps for endpoint details
            </span>
          </div>
        </div>
      </motion.section>

      <footer className="border-t border-border-hairline bg-panel px-6 py-3 mt-auto">
        <p className="text-[11px] font-mono text-muted">
          Lightweight, agent-driven alternative to attack-path-analysis platforms like Wiz/Orca —
          built to run in minutes with zero infrastructure.
        </p>
      </footer>
    </div>
  );
}
