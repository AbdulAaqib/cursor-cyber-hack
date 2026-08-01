// VULNERABLE: fetches any URL the caller supplies with no validation against
// internal/link-local IP ranges (e.g. 169.254.169.254, the AWS instance
// metadata service). An attacker can request
// http://169.254.169.254/latest/meta-data/iam/security-credentials/api-gateway-service
// and this will happily fetch and return it.
export async function fetchExternal(url: string): Promise<string> {
  const res = await fetch(url);
  return res.text();
}
