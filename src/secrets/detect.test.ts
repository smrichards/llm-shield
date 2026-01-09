import { describe, expect, test } from "bun:test";
import type { SecretsDetectionConfig } from "../config";
import type { ChatCompletionRequest } from "../services/llm-client";
import { detectSecrets, extractTextFromRequest } from "./detect";

const defaultConfig: SecretsDetectionConfig = {
  enabled: true,
  action: "block",
  entities: ["OPENSSH_PRIVATE_KEY", "PEM_PRIVATE_KEY"],
  max_scan_chars: 200000,
  redact_placeholder: "<SECRET_REDACTED_{N}>",
  log_detected_types: true,
};

const opensshKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAyK8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
-----END OPENSSH PRIVATE KEY-----`;

const rsaKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyK8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
-----END RSA PRIVATE KEY-----`;

const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
-----END PRIVATE KEY-----`;

const encryptedKey = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIv5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v5Q8v
-----END ENCRYPTED PRIVATE KEY-----`;

describe("detectSecrets", () => {
  test("returns no detection when disabled", () => {
    const config: SecretsDetectionConfig = { ...defaultConfig, enabled: false };
    const result = detectSecrets(opensshKey, config);
    expect(result.detected).toBe(false);
    expect(result.matches).toHaveLength(0);
  });

  test("detects OpenSSH private key", () => {
    const result = detectSecrets(opensshKey, defaultConfig);
    expect(result.detected).toBe(true);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].type).toBe("OPENSSH_PRIVATE_KEY");
    expect(result.matches[0].count).toBe(1);
    expect(result.redactions).toBeDefined();
    expect(result.redactions?.length).toBe(1);
  });

  test("detects RSA private key", () => {
    const result = detectSecrets(rsaKey, defaultConfig);
    expect(result.detected).toBe(true);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].type).toBe("PEM_PRIVATE_KEY");
    expect(result.matches[0].count).toBe(1);
  });

  test("detects generic PRIVATE KEY", () => {
    const result = detectSecrets(privateKey, defaultConfig);
    expect(result.detected).toBe(true);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].type).toBe("PEM_PRIVATE_KEY");
    expect(result.matches[0].count).toBe(1);
  });

  test("detects ENCRYPTED PRIVATE KEY", () => {
    const result = detectSecrets(encryptedKey, defaultConfig);
    expect(result.detected).toBe(true);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].type).toBe("PEM_PRIVATE_KEY");
    expect(result.matches[0].count).toBe(1);
  });

  test("detects multiple secrets of same type", () => {
    const text = `${opensshKey}\n\nSome text\n\n${opensshKey}`;
    const result = detectSecrets(text, defaultConfig);
    expect(result.detected).toBe(true);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].type).toBe("OPENSSH_PRIVATE_KEY");
    expect(result.matches[0].count).toBe(2);
    expect(result.redactions?.length).toBe(2);
  });

  test("detects multiple secrets of different types", () => {
    const text = `${opensshKey}\n\nSome text\n\n${rsaKey}`;
    const result = detectSecrets(text, defaultConfig);
    expect(result.detected).toBe(true);
    expect(result.matches).toHaveLength(2);
    expect(result.matches.find((m) => m.type === "OPENSSH_PRIVATE_KEY")?.count).toBe(1);
    expect(result.matches.find((m) => m.type === "PEM_PRIVATE_KEY")?.count).toBe(1);
  });

  test("avoids false positives - text with BEGIN but not full block", () => {
    const text = "This text contains -----BEGIN OPENSSH PRIVATE KEY----- but not the full key";
    const result = detectSecrets(text, defaultConfig);
    expect(result.detected).toBe(false);
    expect(result.matches).toHaveLength(0);
  });

  test("avoids false positives - just END marker", () => {
    const text = "Some text with -----END OPENSSH PRIVATE KEY----- at the end";
    const result = detectSecrets(text, defaultConfig);
    expect(result.detected).toBe(false);
    expect(result.matches).toHaveLength(0);
  });

  test("handles empty text", () => {
    const result = detectSecrets("", defaultConfig);
    expect(result.detected).toBe(false);
    expect(result.matches).toHaveLength(0);
  });

  test("handles text with no secrets", () => {
    const text = "This is just normal text with no secrets at all.";
    const result = detectSecrets(text, defaultConfig);
    expect(result.detected).toBe(false);
    expect(result.matches).toHaveLength(0);
  });

  test("respects max_scan_chars limit", () => {
    const longText = "a".repeat(100000) + opensshKey;
    const config: SecretsDetectionConfig = { ...defaultConfig, max_scan_chars: 50000 };
    const result = detectSecrets(longText, config);
    // Should not detect because key is after the limit
    expect(result.detected).toBe(false);
  });

  test("detects secrets within max_scan_chars limit", () => {
    const text = opensshKey + "a".repeat(100000);
    const config: SecretsDetectionConfig = { ...defaultConfig, max_scan_chars: 50000 };
    const result = detectSecrets(text, config);
    // Should detect because key is before the limit
    expect(result.detected).toBe(true);
  });

  test("handles max_scan_chars of 0 (no limit)", () => {
    const longText = "a".repeat(100000) + opensshKey;
    const config: SecretsDetectionConfig = { ...defaultConfig, max_scan_chars: 0 };
    const result = detectSecrets(longText, config);
    // Should detect because there's no limit
    expect(result.detected).toBe(true);
  });

  test("only detects configured entity types", () => {
    const config: SecretsDetectionConfig = {
      ...defaultConfig,
      entities: ["OPENSSH_PRIVATE_KEY"],
    };
    const text = `${opensshKey}\n\n${rsaKey}`;
    const result = detectSecrets(text, config);
    expect(result.detected).toBe(true);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].type).toBe("OPENSSH_PRIVATE_KEY");
  });

  test("does not double count RSA keys as generic PRIVATE KEY", () => {
    const text = rsaKey;
    const result = detectSecrets(text, defaultConfig);
    expect(result.detected).toBe(true);
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0].type).toBe("PEM_PRIVATE_KEY");
    expect(result.matches[0].count).toBe(1); // Should be 1, not 2
  });

  test("redactions are sorted by start position descending", () => {
    const text = `${opensshKey}\n\n${rsaKey}`;
    const result = detectSecrets(text, defaultConfig);
    expect(result.redactions).toBeDefined();
    if (result.redactions && result.redactions.length > 1) {
      for (let i = 0; i < result.redactions.length - 1; i++) {
        expect(result.redactions[i].start).toBeGreaterThan(result.redactions[i + 1].start);
      }
    }
  });
});

describe("extractTextFromRequest", () => {
  test("extracts text from simple messages", () => {
    const request: ChatCompletionRequest = {
      messages: [
        { role: "user", content: "Hello world" },
        { role: "assistant", content: "Hi there" },
      ],
    };
    const text = extractTextFromRequest(request);
    expect(text).toBe("Hello world\nHi there");
  });

  test("extracts text from system messages", () => {
    const request: ChatCompletionRequest = {
      messages: [
        { role: "system", content: "You are helpful" },
        { role: "user", content: "Hello" },
      ],
    };
    const text = extractTextFromRequest(request);
    expect(text).toBe("You are helpful\nHello");
  });

  test("filters out empty messages", () => {
    const request: ChatCompletionRequest = {
      messages: [
        { role: "user", content: "Hello" },
        { role: "assistant", content: "" },
        { role: "user", content: "World" },
      ],
    };
    const text = extractTextFromRequest(request);
    expect(text).toBe("Hello\nWorld");
  });

  test("handles single message", () => {
    const request: ChatCompletionRequest = {
      messages: [{ role: "user", content: "Test" }],
    };
    const text = extractTextFromRequest(request);
    expect(text).toBe("Test");
  });

  test("handles empty messages array", () => {
    const request: ChatCompletionRequest = {
      messages: [],
    };
    const text = extractTextFromRequest(request);
    expect(text).toBe("");
  });

  test("extracts all message content in order", () => {
    const request: ChatCompletionRequest = {
      messages: [
        { role: "system", content: "System" },
        { role: "user", content: "User1" },
        { role: "assistant", content: "Assistant" },
        { role: "user", content: "User2" },
      ],
    };
    const text = extractTextFromRequest(request);
    expect(text).toBe("System\nUser1\nAssistant\nUser2");
  });
});
