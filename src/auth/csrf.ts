import { randomBase64Url } from "../encoding";
import { HttpError } from "../http";

export function createCsrfToken(): string {
  return randomBase64Url(24);
}

export function requireCsrfToken(actualToken: string | undefined, expectedToken: string): void {
  if (!actualToken || actualToken !== expectedToken) {
    throw new HttpError(403, "invalid_csrf", "Invalid CSRF token");
  }
}
