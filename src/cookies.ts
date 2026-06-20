export function getCookie(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (!header) {
    return null;
  }

  for (const cookie of header.split(";")) {
    const [rawName, ...rawValueParts] = cookie.trim().split("=");
    if (rawName === name) {
      return rawValueParts.join("=");
    }
  }

  return null;
}
