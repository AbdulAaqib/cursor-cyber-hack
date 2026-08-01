const BLOCKED_HOSTS = ['169.254.169.254', 'metadata.google.internal'];

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
