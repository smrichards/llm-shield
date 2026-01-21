/**
 * Generic masking API routes
 *
 * Provides standalone masking endpoints for clients that need to mask text
 * independently of the OpenAI/Anthropic proxy routes.
 */

import { Hono } from "hono";
import { z } from "zod";
import { getConfig, type SecretsDetectionConfig } from "../config";
import { resolveConflicts, resolveOverlaps } from "../masking/conflict-resolver";
import {
  createPlaceholderContext,
  incrementAndGenerate,
  type PlaceholderContext,
  replaceWithPlaceholders,
} from "../masking/context";
import {
  generatePlaceholder as generatePlaceholderFromFormat,
  generateSecretPlaceholder,
  PII_PLACEHOLDER_FORMAT,
} from "../masking/placeholders";
import type { PIIEntity } from "../pii/detect";
import { getPIIDetector } from "../pii/detect";
import { detectSecrets, type SecretLocation } from "../secrets/detect";
import { getLanguageDetector, type SupportedLanguage } from "../services/language-detector";
import { logRequest } from "../services/logger";

export const apiRoutes = new Hono();

// Request schema
const MaskRequestSchema = z.object({
  text: z.string().trim().min(1, "text is required"),
  language: z.string().optional(),
  startFrom: z.record(z.string(), z.number()).optional(),
  detect: z.array(z.enum(["pii", "secrets"])).optional(),
});

type MaskRequest = z.infer<typeof MaskRequestSchema>;

// Response types
interface MaskEntity {
  type: string;
  placeholder: string;
}

interface MaskResponse {
  masked: string;
  context: Record<string, string>;
  counters: Record<string, number>;
  entities: MaskEntity[];
  language: string;
}

/**
 * Generates a PII placeholder
 */
function generatePIIPlaceholder(entityType: string, context: PlaceholderContext): string {
  return incrementAndGenerate(entityType, context, (type, count) =>
    generatePlaceholderFromFormat(PII_PLACEHOLDER_FORMAT, type, count),
  );
}

/**
 * Generates a secrets placeholder
 */
function generateSecretsPlaceholder(secretType: string, context: PlaceholderContext): string {
  return incrementAndGenerate(secretType, context, generateSecretPlaceholder);
}

/**
 * Masks text with PII entities
 */
function maskWithPII(
  text: string,
  entities: PIIEntity[],
  context: PlaceholderContext,
): { masked: string; entities: MaskEntity[] } {
  if (entities.length === 0) {
    return { masked: text, entities: [] };
  }

  const maskEntities: MaskEntity[] = [];

  const masked = replaceWithPlaceholders(
    text,
    entities,
    context,
    (e) => e.entity_type,
    (type, ctx) => {
      const placeholder = generatePIIPlaceholder(type, ctx);
      maskEntities.push({ type, placeholder });
      return placeholder;
    },
    resolveConflicts,
  );

  return { masked, entities: maskEntities };
}

/**
 * Masks text with secret locations
 */
function maskWithSecrets(
  text: string,
  locations: SecretLocation[],
  context: PlaceholderContext,
): { masked: string; entities: MaskEntity[] } {
  if (locations.length === 0) {
    return { masked: text, entities: [] };
  }

  const maskEntities: MaskEntity[] = [];

  const masked = replaceWithPlaceholders(
    text,
    locations,
    context,
    (loc) => loc.type,
    (type, ctx) => {
      const placeholder = generateSecretsPlaceholder(type, ctx);
      maskEntities.push({ type, placeholder });
      return placeholder;
    },
    resolveOverlaps,
  );

  return { masked, entities: maskEntities };
}

/**
 * POST /api/mask
 *
 * Masks PII and secrets in text. Returns context for client-side unmasking.
 */
apiRoutes.post("/mask", async (c) => {
  const startTime = Date.now();
  const config = getConfig();
  const userAgent = c.req.header("user-agent") || null;

  // Parse and validate request
  const body = await c.req.json().catch(() => null);
  const parseResult = MaskRequestSchema.safeParse(body);

  if (!parseResult.success) {
    return c.json(
      {
        error: {
          message: "Invalid request",
          type: "validation_error",
          details: parseResult.error.errors.map((e) => ({
            path: e.path.join("."),
            message: e.message,
          })),
        },
      },
      400,
    );
  }

  const request: MaskRequest = parseResult.data;
  const detectTypes = request.detect || ["pii", "secrets"];
  const detectPII = detectTypes.includes("pii");
  const detectSecretsFlag = detectTypes.includes("secrets");

  // Initialize context with optional startFrom counters
  const context = createPlaceholderContext();
  if (request.startFrom) {
    for (const [type, count] of Object.entries(request.startFrom)) {
      context.counters[type] = count;
    }
  }

  // Detect language (use provided or auto-detect)
  let language: SupportedLanguage;
  let languageFallback = false;
  if (
    request.language &&
    config.pii_detection.languages.includes(request.language as SupportedLanguage)
  ) {
    language = request.language as SupportedLanguage;
  } else {
    const langResult = getLanguageDetector().detect(request.text);
    language = langResult.language;
    languageFallback = langResult.usedFallback;
  }

  let maskedText = request.text;
  const allEntities: MaskEntity[] = [];
  const piiEntityTypes: string[] = [];
  const secretTypes: string[] = [];
  let scanTimeMs = 0;

  // Detect and mask PII
  if (detectPII) {
    try {
      const piiStartTime = Date.now();
      const detector = getPIIDetector();
      const piiEntities = await detector.detectPII(maskedText, language);
      scanTimeMs = Date.now() - piiStartTime;

      // Apply whitelist filtering
      const whitelist = config.masking.whitelist;
      const filteredEntities = piiEntities.filter((entity) => {
        const detectedText = maskedText.slice(entity.start, entity.end);
        return !whitelist.some(
          (pattern) => pattern.includes(detectedText) || detectedText.includes(pattern),
        );
      });

      const piiResult = maskWithPII(maskedText, filteredEntities, context);
      maskedText = piiResult.masked;
      allEntities.push(...piiResult.entities);

      // Collect unique entity types for logging
      for (const entity of filteredEntities) {
        if (!piiEntityTypes.includes(entity.entity_type)) {
          piiEntityTypes.push(entity.entity_type);
        }
      }
    } catch (error) {
      // Log the error
      logRequest(
        {
          timestamp: new Date().toISOString(),
          mode: "mask",
          provider: "api",
          model: "mask",
          piiDetected: false,
          entities: [],
          latencyMs: Date.now() - startTime,
          scanTimeMs: 0,
          language,
          languageFallback,
          statusCode: 503,
          errorMessage: error instanceof Error ? error.message : "PII detection failed",
        },
        userAgent,
      );

      return c.json(
        {
          error: {
            message: "PII detection failed",
            type: "detection_error",
            details: error instanceof Error ? error.message : "Unknown error",
          },
        },
        503,
      );
    }
  }

  // Detect and mask secrets
  if (detectSecretsFlag && config.secrets_detection.enabled) {
    try {
      // Create a config for detection (always use mask action for API)
      const secretsConfig: SecretsDetectionConfig = {
        enabled: true,
        action: "mask",
        entities: config.secrets_detection.entities,
        max_scan_chars: config.secrets_detection.max_scan_chars,
        log_detected_types: false,
      };

      const secretsResult = detectSecrets(maskedText, secretsConfig);

      if (secretsResult.locations && secretsResult.locations.length > 0) {
        const secretsMaskResult = maskWithSecrets(maskedText, secretsResult.locations, context);
        maskedText = secretsMaskResult.masked;
        allEntities.push(...secretsMaskResult.entities);

        // Collect unique secret types for logging
        for (const match of secretsResult.matches) {
          if (!secretTypes.includes(match.type)) {
            secretTypes.push(match.type);
          }
        }
      }
    } catch (error) {
      // Log the error
      logRequest(
        {
          timestamp: new Date().toISOString(),
          mode: "mask",
          provider: "api",
          model: "mask",
          piiDetected: piiEntityTypes.length > 0,
          entities: piiEntityTypes,
          latencyMs: Date.now() - startTime,
          scanTimeMs,
          language,
          languageFallback,
          statusCode: 503,
          errorMessage: error instanceof Error ? error.message : "Secrets detection failed",
        },
        userAgent,
      );

      return c.json(
        {
          error: {
            message: "Secrets detection failed",
            type: "detection_error",
            details: error instanceof Error ? error.message : "Unknown error",
          },
        },
        503,
      );
    }
  }

  // Log successful request
  logRequest(
    {
      timestamp: new Date().toISOString(),
      mode: "mask",
      provider: "api",
      model: "mask",
      piiDetected: piiEntityTypes.length > 0,
      entities: piiEntityTypes,
      latencyMs: Date.now() - startTime,
      scanTimeMs,
      language,
      languageFallback,
      maskedContent: config.logging.log_masked_content ? maskedText : undefined,
      secretsDetected: secretTypes.length > 0,
      secretsTypes: secretTypes.length > 0 ? secretTypes : undefined,
      statusCode: 200,
    },
    userAgent,
  );

  // Build response
  const response: MaskResponse = {
    masked: maskedText,
    context: context.mapping,
    counters: { ...context.counters },
    entities: allEntities,
    language,
  };

  return c.json(response);
});
