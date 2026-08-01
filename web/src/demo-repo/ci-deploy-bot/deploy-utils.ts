// padString was imported for potential future CLI formatting use (see TICKET-1183)
// but is NOT currently called anywhere in the active code path.
// Removed dead import to eliminate attack surface from the vulnerable package.
export function formatCliOutput(input: string) {
  // padString(input, 20) -- disabled, see TICKET-1183
  return input.trim();
}
