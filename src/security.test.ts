import { describe, expect, it } from "vitest";

import { constantTimeEqual, fromBase64Url, toBase64Url, utf8 } from "./encoding";
import { previewHtmlSecurityHeaders } from "./preview-renderer";
import { resolvePublishActorEmail } from "./publish-principal";
import {
  hashPassword,
  signAccessCookie,
  signPreviewAssetToken,
  verifyAccessCookie,
  verifyPassword,
  verifyPreviewAssetToken,
} from "./security";

describe("encoding helpers", () => {
  it("round-trips base64url values", () => {
    const encoded = toBase64Url(utf8("hello world"));

    expect(encoded).toBe("aGVsbG8gd29ybGQ");
    expect(new TextDecoder().decode(fromBase64Url(encoded))).toBe("hello world");
  });

  it("compares strings without returning true for different lengths", () => {
    expect(constantTimeEqual("abc", "abc")).toBe(true);
    expect(constantTimeEqual("abc", "abd")).toBe(false);
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
  });
});

describe("password hashing", () => {
  it("verifies matching passwords and rejects non-matches", async () => {
    const stored = await hashPassword("correct horse battery", "pepper", undefined, 1_000);

    await expect(verifyPassword("correct horse battery", "pepper", stored.hash, stored.salt, stored.iterations)).resolves.toBe(
      true,
    );
    await expect(verifyPassword("wrong horse battery", "pepper", stored.hash, stored.salt, stored.iterations)).resolves.toBe(
      false,
    );
  });
});

describe("access cookies", () => {
  it("verifies signed access cookies", async () => {
    const token = await signAccessCookie(
      {
        slug: "abc123",
        passwordVersion: 1,
        expiresAt: Date.now() + 60_000,
      },
      "secret",
    );

    await expect(verifyAccessCookie(token, "secret", "abc123", 1)).resolves.toBe(true);
    await expect(verifyAccessCookie(token, "secret", "abc123", 2)).resolves.toBe(false);
    await expect(verifyAccessCookie(`${token}x`, "secret", "abc123", 1)).resolves.toBe(false);
  });
});

describe("preview asset tokens", () => {
  it("verifies signed asset URLs and rejects wrong or expired assets", async () => {
    const token = await signPreviewAssetToken(
      {
        slug: "abc123",
        assetId: "asset123",
        passwordVersion: 1,
        expiresAt: Date.now() + 60_000,
      },
      "secret",
    );

    await expect(verifyPreviewAssetToken(token, "secret", "abc123", "asset123", 1)).resolves.toBe(true);
    await expect(verifyPreviewAssetToken(token, "secret", "abc123", "other-asset", 1)).resolves.toBe(false);
    await expect(verifyPreviewAssetToken(token, "secret", "abc123", "asset123", 2)).resolves.toBe(false);
    await expect(verifyPreviewAssetToken(token, "secret", "abc123", "asset123", 1, Date.now() + 120_000)).resolves.toBe(
      false,
    );
  });
});

describe("preview HTML security headers", () => {
  it("sandboxes uploaded HTML and blocks script execution by default", () => {
    const csp = previewHtmlSecurityHeaders("https://preview.example.test")["Content-Security-Policy"];

    expect(csp).toContain("sandbox");
    expect(csp).toContain("script-src 'none'");
    expect(csp).toContain("script-src-attr 'none'");
    expect(csp).toContain("form-action 'none'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("worker-src 'none'");
    expect(csp).toContain("img-src https://preview.example.test data: blob:");
    expect(csp).not.toContain("script-src 'unsafe-inline'");
    expect(csp).not.toContain("img-src https: data:");
  });

  it("allows opt-in scripts without same-origin, network, forms, frames, or workers", () => {
    const csp = previewHtmlSecurityHeaders("https://preview.example.test", {
      allowScripts: true,
    })["Content-Security-Policy"];

    expect(csp).toContain("sandbox allow-scripts");
    expect(csp).not.toContain("allow-same-origin");
    expect(csp).toContain("script-src 'unsafe-inline'");
    expect(csp).toContain("script-src-attr 'none'");
    expect(csp).toContain("connect-src 'none'");
    expect(csp).toContain("form-action 'none'");
    expect(csp).toContain("frame-src 'none'");
    expect(csp).toContain("worker-src 'none'");
    expect(csp).toContain("navigate-to 'none'");
    expect(csp).not.toContain("script-src 'none'");
    expect(csp).not.toContain("connect-src https:");
    expect(csp).not.toContain("script-src https:");
  });
});

describe("trusted API actor identity", () => {
  it("uses the configured service identity instead of request body identity", () => {
    expect(
      resolvePublishActorEmail({
        TRUSTED_PUBLISHER_EMAIL: "HTML-Sharing@Example.com",
        PUBLISHER_EMAIL_DOMAIN: "example.com",
      }),
    ).toBe("html-sharing@example.com");
  });

  it("requires a configured trusted identity and allowed domain", () => {
    expect(() => resolvePublishActorEmail({ PUBLISHER_EMAIL_DOMAIN: "example.com" })).toThrow(
      "Trusted publisher identity is not configured",
    );
    expect(() => resolvePublishActorEmail({ TRUSTED_PUBLISHER_EMAIL: "publisher@example.com" })).toThrow(
      "Publisher email domain is not configured",
    );
    expect(() =>
      resolvePublishActorEmail({
        TRUSTED_PUBLISHER_EMAIL: "attacker@other.example.com",
        PUBLISHER_EMAIL_DOMAIN: "example.com",
      }),
    ).toThrow("publisherEmail must be a @example.com address");
  });

  it("allows forks to configure their own trusted publisher domain", () => {
    expect(
      resolvePublishActorEmail({
        TRUSTED_PUBLISHER_EMAIL: "Publisher@Internal.example",
        PUBLISHER_EMAIL_DOMAIN: "internal.example",
      }),
    ).toBe("publisher@internal.example");
  });

  it("uses a verified request actor when provided", () => {
    expect(
      resolvePublishActorEmail(
        {
          TRUSTED_PUBLISHER_EMAIL: "service@example.com",
          PUBLISHER_EMAIL_DOMAIN: "example.com",
        },
        "Publisher@Example.com",
      ),
    ).toBe("publisher@example.com");
  });
});
