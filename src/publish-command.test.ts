import { describe, expect, it } from "vitest";

import { parsePreviewPublishInput, parseRotatePasswordCommand } from "./publish-command";

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
          password: "abcde",
        },
        {},
      ).expiresAt,
    ).toBeNull();
  });

  it("keeps custom slugs optional and exact", () => {
    expect(
      parsePreviewPublishInput(
        {
          title: "Random slug",
          html: completeHtml,
          password: "abcde",
        },
        {},
      ).slug,
    ).toBeNull();

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

  it("keeps scripts disabled by default and accepts explicit interactive mode", () => {
    expect(
      parsePreviewPublishInput(
        {
          title: "Static preview",
          html: completeHtml,
          password: "abcde",
        },
        {},
      ).allowScripts,
    ).toBe(false);

    expect(
      parsePreviewPublishInput(
        {
          title: "Interactive preview",
          html: completeHtml,
          password: "abcde",
          allowScripts: true,
        },
        {},
      ).allowScripts,
    ).toBe(true);
  });

  it("rejects non-boolean interactive mode values", () => {
    expect(() =>
      parsePreviewPublishInput(
        {
          title: "Bad mode",
          html: completeHtml,
          password: "abcde",
          allowScripts: "true",
        },
        {},
      ),
    ).toThrow("allowScripts must be a boolean");
  });

  it("accepts image attachments separately from the HTML string", () => {
    const input = parsePreviewPublishInput(
      {
        title: "Image preview",
        html: '<!doctype html><html><body><img src="cid:proof.png"></body></html>',
        password: "abcde",
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
        },
        {},
      ),
    ).toThrow("Password must be between 5 and 256 characters");

    expect(() => parseRotatePasswordCommand({ password: "abcd" })).toThrow(
      "Password must be between 5 and 256 characters",
    );
  });
});
