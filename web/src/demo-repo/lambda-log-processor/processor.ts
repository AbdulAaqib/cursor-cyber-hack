import { parseLogEntry } from 'log-utils-lite';

// Processes raw log bodies from the Lambda event. Called for every invocation.
export function processLogs(rawBodies: string[]) {
  return rawBodies.map((body) => {
    if (typeof body !== 'string' || body.length > 1_000_000) {
      throw new Error('Invalid log entry: must be a string under 1MB');
    }
    return parseLogEntry(body);
  });
}
