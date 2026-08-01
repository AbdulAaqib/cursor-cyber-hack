'use client';

import Link from 'next/link';
import { motion, useReducedMotion } from 'framer-motion';

const PIPELINE_STAGES = [
  {
    label: 'Snyk finding',
    description: 'Patient zero — the vulnerability report that starts the investigation.',
  },
  {
    label: 'Code reachability',
    description:
      "Agent reads real source files, follows the import/call chain itself — is the vulnerable function actually invoked, or dead code?",
  },
  {
    label: 'AWS IAM blast-radius',
    description:
      "Agent walks a real AWS account's IAM trust graph (AssumeRole / PassRole / AttachRolePolicy), reading raw policy actions/resources rather than trusting a pre-baked severity tag.",
  },
  {
    label: 'Holistic verdict',
    description:
      "Severity + a plain-English attack narrative: \"if exploited, here's exactly what happens and why it matters.\"",
  },
  {
    label: 'Human-approved remediation',
    description:
      'Agent proposes a fix (AWS policy detach, or a real GitHub PR with a code patch); a human must click "Confirm & Apply" before anything actually executes.',
  },
];

const CASE_STUDIES = [
  {
    id: 'SNYK-2026-001',
    package: 'log-utils-lite@1.2.3',
    cvss: 6.5,
    class: 'Remote Code Execution',
    verdict: 'CRITICAL',
    summary:
      'Vulnerable parseLogEntry is called directly on every Lambda invocation with attacker-controlled input, leading to full account takeover via AdministratorAccess.',
  },
  {
    id: 'SNYK-2026-002',
    package: 'string-pad-utility@0.0.9',
    cvss: 9.1,
    class: 'Dead code — never invoked',
    verdict: 'LOW',
    summary:
      'The vulnerable padString call is commented out — imported, never invoked, dead code. No exploit path exists regardless of IAM permissions.',
  },
  {
    id: 'SNYK-2026-003',
    package: 'url-fetch-proxy@2.1.0',
    cvss: 7.4,
    class: 'SSRF to credential theft',
    verdict: null,
    summary:
      'SSRF via unvalidated URL fetching reaches the instance metadata service, stealing live IAM credentials. The stolen role chain reaches a role with real access to customer payment data (s3:GetObject / s3:ListBucket on customer-payments-data).',
  },
];

const VERDICT_BADGE: Record<string, string> = {
  CRITICAL: 'bg-critical/15 border-critical text-critical',
  HIGH: 'bg-high/15 border-high text-high',
  MEDIUM: 'bg-medium/15 border-medium text-medium',
  LOW: 'bg-low/15 border-low text-low',
};

function LighthouseBeacon() {
  const reduced = useReducedMotion();

  return (
    <div className="relative w-32 h-32 md:w-40 md:h-40 flex-shrink-0">
      <svg
        viewBox="0 0 100 100"
        className="w-full h-full"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <radialGradient id="beamGlow" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0%" stopColor="#E89B2E" stopOpacity="0.35" />
            <stop offset="100%" stopColor="#E89B2E" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="beamGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#E89B2E" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#E89B2E" stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* Ambient glow behind lantern */}
        <circle cx="50" cy="22" r="16" fill="url(#beamGlow)" opacity="0.6" />

        {/* Sweeping beam */}
        {!reduced && (
          <motion.g
            style={{ originX: '50px', originY: '22px' }}
            animate={{ rotate: [-25, 25, -25] }}
            transition={{
              duration: 5,
              repeat: Infinity,
              ease: 'easeInOut',
            }}
          >
            <path
              d="M 50 22 L 95 5 L 95 39 Z"
              fill="url(#beamGradient)"
              opacity="0.5"
            />
          </motion.g>
        )}
        {reduced && (
          <path
            d="M 50 22 L 95 5 L 95 39 Z"
            fill="url(#beamGradient)"
            opacity="0.3"
          />
        )}

        {/* Tower base */}
        <rect x="38" y="78" width="24" height="6" rx="1.5" fill="#10182B" />

        {/* Tower body, tapered, striped */}
        <path
          d="M 44 28 L 56 28 L 60 78 L 40 78 Z"
          fill="#FFFFFF"
          stroke="#10182B"
          strokeWidth="1.2"
        />
        <path d="M 43 38 L 57 38 L 58 46 L 42 46 Z" fill="#D93B4A" />
        <path d="M 41 56 L 59 56 L 60 64 L 40 64 Z" fill="#D93B4A" />

        {/* Roof */}
        <path d="M 40 28 L 50 20 L 60 28 Z" fill="#10182B" />

        {/* Lantern room */}
        <rect x="43" y="20" width="14" height="8" rx="1" fill="#10182B" />
        <circle cx="50" cy="24" r="3" fill="#E89B2E" />
      </svg>
    </div>
  );
}

export default function HomePage() {
  const reduced = useReducedMotion();

  const heroContainer = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: reduced ? 0 : 0.1,
        delayChildren: reduced ? 0 : 0.05,
      },
    },
  };

  const heroItem = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: reduced ? 0 : 0.5, ease: 'easeOut' as const },
    },
  };

  const reveal = {
    hidden: { opacity: 0, y: 12 },
    visible: (i: number) => ({
      opacity: 1,
      y: 0,
      transition: {
        duration: reduced ? 0 : 0.4,
        ease: 'easeOut' as const,
        delay: reduced ? 0 : i * 0.08,
      },
    }),
  };

  return (
    <div className="flex flex-col min-h-[calc(100vh-48px)] bg-background text-foreground font-sans">
      {/* Hero */}
      <section className="border-b border-border-hairline px-6 py-16 md:py-20">
        <div className="max-w-4xl mx-auto">
          <motion.div
            variants={heroContainer}
            initial="hidden"
            animate="visible"
            className="flex flex-col md:flex-row md:items-center md:gap-10"
          >
            <div className="flex-1">
              <motion.h1
                variants={heroItem}
                className="font-mono text-2xl md:text-4xl font-bold tracking-tight leading-tight mb-4"
              >
                CVSS tells you a vulnerability exists.
                <br />
                <span className="text-accent">This tells you what happens if it&apos;s exploited.</span>
              </motion.h1>
              <motion.p
                variants={heroItem}
                className="text-muted font-mono text-sm md:text-base mb-8 max-w-2xl"
              >
                The average enterprise employee holds ~96,000 permissions. No human traces
                reachability across a graph that large by hand.
              </motion.p>
              <motion.div variants={heroItem} className="flex flex-wrap gap-3">
                <Link
                  href="/console"
                  className="rounded bg-accent px-5 py-2.5 font-mono text-xs font-semibold text-[#10182B] transition-opacity hover:opacity-90"
                >
                  Launch Console
                </Link>
                <Link
                  href="/workflows"
                  className="rounded border border-border-hairline bg-panel px-5 py-2.5 font-mono text-xs font-semibold text-foreground transition-opacity hover:opacity-80"
                >
                  View Workflows
                </Link>
              </motion.div>
            </div>
            <motion.div variants={heroItem} className="mt-8 md:mt-0 flex justify-center md:justify-end">
              <LighthouseBeacon />
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* Pipeline diagram */}
      <section className="border-b border-border-hairline px-6 py-12">
        <div className="max-w-4xl mx-auto">
          <motion.div
            className="text-[11px] font-mono uppercase tracking-wider text-muted mb-6"
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true, amount: 0.5 }}
            transition={{ duration: reduced ? 0 : 0.4 }}
          >
            The Pipeline
          </motion.div>
          <div className="flex flex-col gap-0">
            {PIPELINE_STAGES.map((stage, i) => (
              <motion.div
                key={stage.label}
                className="flex items-start gap-4"
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true, amount: 0.5 }}
                custom={i}
                variants={reveal}
              >
                <div className="flex flex-col items-center">
                  <div className="rounded border border-border-hairline bg-panel px-3 py-2 font-mono text-xs text-foreground min-w-[140px]">
                    {stage.label}
                  </div>
                  {i < PIPELINE_STAGES.length - 1 && (
                    <div className="h-6 w-px bg-border-hairline my-1" />
                  )}
                </div>
                <p className="text-sm text-muted pt-2 max-w-lg">{stage.description}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Case studies */}
      <section className="border-b border-border-hairline px-6 py-12">
        <div className="max-w-4xl mx-auto">
          <motion.div
            className="text-[11px] font-mono uppercase tracking-wider text-muted mb-6"
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true, amount: 0.5 }}
            transition={{ duration: reduced ? 0 : 0.4 }}
          >
            Case Studies
          </motion.div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {CASE_STUDIES.map((cs, i) => (
              <motion.div
                key={cs.id}
                initial="hidden"
                whileInView="visible"
                viewport={{ once: true, amount: 0.3 }}
                custom={i}
                variants={reveal}
                whileHover={{ y: -3, transition: { duration: 0.2 } }}
              >
                <Link
                  href={`/console?finding=${cs.id}`}
                  className="block rounded border border-border-hairline bg-panel p-4 transition-colors hover:border-accent/30 group"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-xs text-foreground font-semibold">
                      {cs.id}
                    </span>
                    {cs.verdict ? (
                      <span
                        className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-bold ${VERDICT_BADGE[cs.verdict]}`}
                      >
                        {cs.verdict}
                      </span>
                    ) : (
                      <span className="rounded border border-muted/30 px-1.5 py-0.5 font-mono text-[10px] text-muted">
                        reaches customer payment data
                      </span>
                    )}
                  </div>
                  <div className="font-mono text-[11px] text-accent mb-2">
                    {cs.package} (CVSS {cs.cvss})
                  </div>
                  <div className="text-xs text-muted mb-2">{cs.class}</div>
                  <p className="text-xs text-foreground/80 leading-relaxed">{cs.summary}</p>
                </Link>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Honest positioning */}
      <section className="px-6 py-10">
        <div className="max-w-4xl mx-auto">
          <motion.p
            className="text-sm text-muted leading-relaxed"
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            viewport={{ once: true, amount: 0.5 }}
            transition={{ duration: reduced ? 0 : 0.5, ease: 'easeOut' as const }}
          >
            This is not a claim to have invented &ldquo;attack path analysis&rdquo; — Wiz and Orca
            Security have run mature, funded platforms in this category for years. The
            differentiation here is specific: a{' '}
            <strong className="text-foreground">lightweight, transparent, agent-driven</strong>{' '}
            alternative built to run in minutes with zero infrastructure, where the reasoning is
            visible (every claim traces back to a real file or a real API response) rather than a
            black-box score.
          </motion.p>
        </div>
      </section>

      <footer className="border-t border-border-hairline bg-panel px-6 py-3 mt-auto">
        <p className="text-[11px] font-mono text-muted">
          Lightweight, agent-driven alternative to attack-path-analysis platforms like Wiz/Orca —
          built to run in minutes with zero infrastructure.
        </p>
      </footer>
    </div>
  );
}
