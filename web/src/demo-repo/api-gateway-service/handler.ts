import { fetchExternal } from './fetcher';
import { formatResponse } from './response-formatter';

export async function handler(req: { query: { url: string } }) {
  const raw = await fetchExternal(req.query.url);
  return formatResponse(raw);
}
