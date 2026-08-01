// eslint-disable-next-line @typescript-eslint/no-unused-vars -- intentionally unused: this is the "dead code" demo scenario the agent must detect
import { padString } from 'string-pad-utility';

// padString is imported for potential future CLI formatting use (see TICKET-1183)
// but is NOT currently called anywhere in the active code path.
export function formatCliOutput(input: string) {
  // padString(input, 20) -- disabled, see TICKET-1183
  return input.trim();
}
