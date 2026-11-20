import { describe, expect, it } from "vitest";
import { resourceKey } from "../src/ui/attachments";

describe("resourceKey", () => {
  const base = "capacitor://localhost/_capacitor_file_/var/mobile/Containers/Data/Application/X/Documents/StrongboxTest/";

  it("drops the query string", () => {
    expect(resourceKey(base + "a.png?1763600000000")).toBe(base + "a.png");
  });

  it("matches escaped and unescaped spellings of a non-ASCII path", () => {
    const raw = base + "私密/图片/照片.png";
    expect(resourceKey(encodeURI(raw) + "?123")).toBe(resourceKey(raw));
  });

  it("matches NFD and NFC spellings", () => {
    const nfc = base + "café.png";
    const nfd = nfc.normalize("NFD");
    expect(nfd).not.toBe(nfc);
    expect(resourceKey(encodeURI(nfd))).toBe(resourceKey(nfc));
  });

  it("keeps a malformed escape as is", () => {
    expect(resourceKey("app://x/100%.png")).toBe("app://x/100%.png");
  });
});
