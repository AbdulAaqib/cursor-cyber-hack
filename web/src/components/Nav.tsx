'use client';

import Image from 'next/image';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

const NAV_LINKS = [
  { href: '/console', label: 'Console' },
  { href: '/workflows', label: 'Workflows' },
];

export default function Nav() {
  const pathname = usePathname();

  return (
    <nav className="flex items-center justify-between border-b border-border-hairline bg-panel px-6 py-2.5">
      <Link href="/" className="flex items-center gap-2.5">
        <Image src="/logo.svg" alt="" width={20} height={20} className="rounded" />
        <span className="font-mono text-xs font-semibold tracking-wide text-foreground hidden sm:inline">
          EXPOSURE REASONING AGENT
        </span>
      </Link>
      <div className="flex items-center gap-5">
        {NAV_LINKS.map((link) => {
          const active = pathname === link.href;
          return (
            <Link
              key={link.href}
              href={link.href}
              className={`font-mono text-xs tracking-wide transition-colors ${
                active ? 'text-accent' : 'text-muted hover:text-foreground'
              }`}
            >
              {active && (
                <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-accent" />
              )}
              {link.label}
            </Link>
          );
        })}
      </div>
    </nav>
  );
}
