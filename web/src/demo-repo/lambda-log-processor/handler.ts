export async function handler(event: { Records: { body: string }[] }) {
  const rawBodies = event.Records.map((r) => r.body);
  return processLogs(rawBodies);
}

import { processLogs } from './processor';
