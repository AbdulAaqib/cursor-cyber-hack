// Returns the raw fetched body directly to the caller -- including, if the
// SSRF above was used to hit the instance metadata service, the role's live
// temporary AWS credentials.
export function formatResponse(rawBody: string) {
  return { status: 200, body: rawBody };
}
