import { parseLogEntry } from 'log-utils-lite';

// Processes raw log bodies from the Lambda event. Called for every invocation.
export function processLogs(rawBodies: string[]) {
  return rawBodies.map((body) => parseLogEntry(body));
}
