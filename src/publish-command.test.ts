import { describe, expect, it } from "vitest";

import { parsePreviewHtmlUpdateInput, parsePreviewPublishInput, parseRotatePasswordCommand } from "./publish-command";

const completeHtml = "<!doctype html><html><body><h1>Preview</h1></body></html>";
const tinyPngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=";

describe("publish command password validation", () => {
  it("does not set an expiry when expiresAt is omitted", () => {
    expect(
      parsePreviewPublishInput(
        {
          title: "No expiry",
          html: completeHtml,
          slug: "no-expiry",
          password: "abcde",
        },
        {},
      ).expiresAt,
    ).toBeNull();
  });

  it("requires a slug and keeps it exact", () => {
    expect(() =>
      parsePreviewPublishInput(
        {
          title: "Missing slug",
          html: completeHtml,
          password: "abcde",
        },
        {},
      ),
    ).toThrow("slug is required");

    expect(
      parsePreviewPublishInput(
        {
          title: "Custom slug",
          html: completeHtml,
          password: "abcde",
          slug: "hello-world-test",
        },
        {},
      ).slug,
    ).toBe("hello-world-test");
  });

  it.each([
    "ab",
    "Hello-World",
    "hello_world",
    "hello.world",
    "hello/world",
    "hello world",
    "-hello",
    "hello-",
    "hello--world",
    "a".repeat(81),
  ])("rejects invalid custom slug %j", (slug) => {
    expect(() =>
      parsePreviewPublishInput(
        {
          title: "Bad slug",
          html: completeHtml,
          password: "abcde",
          slug,
        },
        {},
      ),
    ).toThrow("Slug must be 3-80 characters and use lowercase letters, numbers, and single hyphens");
  });

  it("keeps explicit future expiry timestamps", () => {
    expect(
      parsePreviewPublishInput(
        {
          title: "Explicit expiry",
          html: completeHtml,
          password: "abcde",
          slug: "explicit-expiry",
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
          slug: "short-password",
        },
        {},
      ).password,
    ).toBe("abcde");

    expect(parseRotatePasswordCommand({ password: "abcde" }).password).toBe("abcde");
  });

  it("rejects removed allowScripts input", () => {
    expect(() =>
      parsePreviewPublishInput(
        {
          title: "Bad mode",
          html: completeHtml,
          password: "abcde",
          slug: "bad-mode",
          allowScripts: true,
        },
        {},
      ),
    ).toThrow("allowScripts is not supported");

    expect(() =>
      parsePreviewHtmlUpdateInput(
        {
          html: completeHtml,
          allowScripts: true,
        },
        {},
      ),
    ).toThrow("allowScripts is not supported");
  });

  it("accepts image attachments separately from the HTML string", () => {
    const input = parsePreviewPublishInput(
      {
        title: "Image preview",
        html: '<!doctype html><html><body><img src="cid:proof.png"></body></html>',
        password: "abcde",
        slug: "image-preview",
        images: [
          {
            name: "proof.png",
            mimeType: "image/png",
            dataBase64: tinyPngBase64,
          },
        ],
      },
      {},
    );

    expect(input.images).toHaveLength(1);
    expect(input.images[0]).toMatchObject({
      name: "proof.png",
      contentType: "image/png",
      byteSize: 68,
    });
  });

  it("rejects duplicate or unsafe image names", () => {
    expect(() =>
      parsePreviewPublishInput(
        {
          title: "Bad image",
          html: completeHtml,
          password: "abcde",
          slug: "bad-image",
          images: [
            {
              name: "../proof.png",
              mimeType: "image/png",
              dataBase64: tinyPngBase64,
            },
          ],
        },
        {},
      ),
    ).toThrow("images[0].name must use letters, numbers, dots, underscores, or dashes");

    expect(() =>
      parsePreviewPublishInput(
        {
          title: "Duplicate image",
          html: completeHtml,
          password: "abcde",
          slug: "duplicate-image",
          images: [
            {
              name: "proof.png",
              mimeType: "image/png",
              dataBase64: tinyPngBase64,
            },
            {
              name: "PROOF.png",
              mimeType: "image/png",
              dataBase64: tinyPngBase64,
            },
          ],
        },
        {},
      ),
    ).toThrow("Image name must be unique: PROOF.png");
  });

  it("rejects viewer passwords shorter than 5 characters", () => {
    expect(() =>
      parsePreviewPublishInput(
        {
          title: "Too short",
          html: completeHtml,
          password: "abcd",
          slug: "too-short",
        },
        {},
      ),
    ).toThrow("Password must be between 5 and 256 characters");

    expect(() => parseRotatePasswordCommand({ password: "abcd" })).toThrow(
      "Password must be between 5 and 256 characters",
    );
  });

  it("parses HTML updates without accepting password changes", () => {
    const input = parsePreviewHtmlUpdateInput(
      {
        title: "Updated preview",
        html: completeHtml,
        expiresAt: null,
        sourceUrl: "https://source.example.test/artifacts/updated",
      },
      {},
    );

    expect(input).toMatchObject({
      title: "Updated preview",
      html: completeHtml,
      images: [],
      expiresAt: null,
      sourceUrl: "https://source.example.test/artifacts/updated",
    });
  });

  it("rejects password on HTML updates so rotation stays explicit", () => {
    expect(() =>
      parsePreviewHtmlUpdateInput(
        {
          html: completeHtml,
          password: "new password",
        },
        {},
      ),
    ).toThrow("password is not supported");
  });
});
