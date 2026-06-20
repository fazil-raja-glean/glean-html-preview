import { requirePublishAdminAccess } from "./admin-auth";
import { constantTimeEqual } from "./encoding";
import { HttpError, requireBearerToken } from "./http";
import { INTERNAL_PUBLISH_ACTOR_EMAIL_HEADER, INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER } from "./mcp";
import { isLocalDevelopmentRequest } from "./origin-policy";

export interface PublishPrincipal {
  actorEmail: string;
}

export interface PublishPrincipalEnv {
  PUBLISH_ACCESS_AUD?: string;
  PUBLISH_ACCESS_TEAM_DOMAIN?: string;
  PUBLISH_ADMIN_LOCAL_BYPASS_SECRET?: string;
  PUBLISH_API_TOKEN: string;
  PUBLISH_INTERNAL_SERVICE_TOKEN?: string;
  PUBLISHER_EMAIL_DOMAIN?: string;
  TRUSTED_PUBLISHER_EMAIL?: string;
}

export async function requirePublishPrincipal(
  request: Request,
  env: PublishPrincipalEnv,
  url: URL,
): Promise<PublishPrincipal> {
  requireBearerToken(request, env.PUBLISH_API_TOKEN);
  const actorEmail = hasValidInternalPublishServiceToken(request, env)
    ? internalPublishActorEmail(request)
    : (
        await requirePublishAdminAccess(request, env, {
          isLocalDevelopment: isLocalDevelopmentRequest(request, url),
        })
      ).email;

  return {
    actorEmail: resolvePublishActorEmail(env, actorEmail ?? undefined),
  };
}

export function resolvePublishActorEmail(
  env: Pick<PublishPrincipalEnv, "PUBLISHER_EMAIL_DOMAIN" | "TRUSTED_PUBLISHER_EMAIL">,
  actorEmail?: string,
): string {
  const email = (actorEmail ?? env.TRUSTED_PUBLISHER_EMAIL)?.trim().toLowerCase();
  if (!email) {
    throw new HttpError(500, "missing_publisher_identity", "Trusted publisher identity is not configured");
  }

  const domain = env.PUBLISHER_EMAIL_DOMAIN?.trim().toLowerCase();
  if (!domain) {
    throw new HttpError(500, "missing_publisher_email_domain", "Publisher email domain is not configured");
  }

  validatePublisherEmail(email, domain);
  return email;
}

function hasValidInternalPublishServiceToken(
  request: Request,
  env: Pick<PublishPrincipalEnv, "PUBLISH_INTERNAL_SERVICE_TOKEN">,
): boolean {
  const actualToken = request.headers.get(INTERNAL_PUBLISH_SERVICE_TOKEN_HEADER);
  if (!actualToken) {
    return false;
  }

  if (!env.PUBLISH_INTERNAL_SERVICE_TOKEN) {
    throw new HttpError(500, "missing_internal_service_token", "Internal publish service token is not configured");
  }

  if (!constantTimeEqual(actualToken, env.PUBLISH_INTERNAL_SERVICE_TOKEN)) {
    throw new HttpError(403, "invalid_internal_service_token", "Invalid internal publish service token");
  }

  return true;
}

function internalPublishActorEmail(request: Request): string | null {
  const actorEmail = request.headers.get(INTERNAL_PUBLISH_ACTOR_EMAIL_HEADER);
  return actorEmail && actorEmail.trim() !== "" ? actorEmail : null;
}

function validatePublisherEmail(email: string, domain: string): void {
  const suffix = `@${domain.toLowerCase()}`;
  if (!email.endsWith(suffix) || email.length <= suffix.length) {
    throw new HttpError(400, "invalid_publisher", `publisherEmail must be a ${suffix} address`);
  }
}
