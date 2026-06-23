import { describe, expect, it } from "vitest";

import { parsePreviewPublishInput, parseRotatePasswordCommand } from "./publish-command";

const completeHtml = "<!doctype html><html><body><h1>Preview</h1></body></html>";

describe("publish command password validation", () => {
  it("does not set an expiry when expiresAt is omitted", () => {
    expect(
      parsePreviewPublishInput(
        {
          title: "No expiry",
          html: completeHtml,
          password: "abcde",
        },
        {},
      ).expiresAt,
    ).toBeNull();
  });

  it("keeps explicit future expiry timestamps", () => {
    expect(
      parsePreviewPublishInput(
        {
          title: "Explicit expiry",
          html: completeHtml,
          password: "abcde",
          expiresAt: "2099-01-01T00:00:00.000Z",
        },
        {},
      ).expiresAt,
    ).toBe("2099-01-01T00:00:00.000Z");
  });

  it("accepts 5-character viewer passwords", () => {
    expect(
      parsePreviewPublishInput(
        {
          title: "Short password",
          html: completeHtml,
          password: "abcde",
        },
        {},
      ).password,
    ).toBe("abcde");

    expect(parseRotatePasswordCommand({ password: "abcde" }).password).toBe("abcde");
  });

  it("rejects viewer passwords shorter than 5 characters", () => {
    expect(() =>
      parsePreviewPublishInput(
        {
          title: "Too short",
          html: completeHtml,
          password: "abcd",
        },
        {},
      ),
    ).toThrow("Password must be between 5 and 256 characters");

    expect(() => parseRotatePasswordCommand({ password: "abcd" })).toThrow(
      "Password must be between 5 and 256 characters",
    );
  });
});
