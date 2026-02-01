/**
 * ai-guardrails
 * Input/output validation and safety for AI applications
 * 
 * @packageDocumentation
 */

import { z } from 'zod';

// ============================================================================
// Types
// ============================================================================

export interface ValidationResult {
  valid: boolean;
  issues: ValidationIssue[];
  sanitized?: string;
}

export interface ValidationIssue {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  position?: { start: number; end: number };
  detected?: string;
}

export interface GuardrailConfig {
  maxLength?: number;
  allowedTopics?: string[];
  blockedTopics?: string[];
  detectPII?: boolean;
  detectPromptInjection?: boolean;
  customPatterns?: Array<{ name: string; pattern: RegExp; severity: ValidationIssue['severity'] }>;
}

// ============================================================================
// PII Detection
// ============================================================================

const PII_PATTERNS = {
  email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  phone: /(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
  ssn: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/g,
  creditCard: /\b(?:\d{4}[-.\s]?){3}\d{4}\b/g,
  ipAddress: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  dateOfBirth: /\b(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b/g,
};

/**
 * Detect PII in text
 */
export function detectPII(text: string): Array<{
  type: string;
  value: string;
  position: { start: number; end: number };
}> {
  const findings: Array<{
    type: string;
    value: string;
    position: { start: number; end: number };
  }> = [];

  for (const [type, pattern] of Object.entries(PII_PATTERNS)) {
    let match;
    const regex = new RegExp(pattern.source, pattern.flags);
    while ((match = regex.exec(text)) !== null) {
      findings.push({
        type,
        value: match[0],
        position: { start: match.index, end: match.index + match[0].length },
      });
    }
  }

  return findings;
}

/**
 * Redact PII from text
 */
export function redactPII(text: string, replacement = '[REDACTED]'): string {
  let result = text;

  for (const pattern of Object.values(PII_PATTERNS)) {
    result = result.replace(new RegExp(pattern.source, pattern.flags), replacement);
  }

  return result;
}

// ============================================================================
// Prompt Injection Detection
// ============================================================================

const INJECTION_PATTERNS = [
  { pattern: /ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?)/i, name: 'ignore_previous' },
  { pattern: /disregard\s+(all\s+)?(previous|above|prior)/i, name: 'disregard' },
  { pattern: /forget\s+(everything|all|what)/i, name: 'forget' },
  { pattern: /new\s+instructions?:/i, name: 'new_instructions' },
  { pattern: /system\s*:\s*/i, name: 'system_prefix' },
  { pattern: /\[INST\]/i, name: 'inst_tag' },
  { pattern: /<\|im_start\|>/i, name: 'im_start' },
  { pattern: /you\s+are\s+now\s+/i, name: 'role_change' },
  { pattern: /act\s+as\s+(if\s+you\s+are\s+|a\s+)/i, name: 'act_as' },
  { pattern: /pretend\s+(you\s+are|to\s+be)/i, name: 'pretend' },
  { pattern: /override\s+(your\s+)?(instructions?|programming)/i, name: 'override' },
  { pattern: /jailbreak/i, name: 'jailbreak' },
  { pattern: /DAN\s*mode/i, name: 'dan_mode' },
];

/**
 * Detect prompt injection attempts
 */
export function detectPromptInjection(text: string): Array<{
  type: string;
  matched: string;
  position: { start: number; end: number };
}> {
  const findings: Array<{
    type: string;
    matched: string;
    position: { start: number; end: number };
  }> = [];

  for (const { pattern, name } of INJECTION_PATTERNS) {
    const match = pattern.exec(text);
    if (match) {
      findings.push({
        type: name,
        matched: match[0],
        position: { start: match.index, end: match.index + match[0].length },
      });
    }
  }

  return findings;
}

/**
 * Check if text contains prompt injection
 */
export function hasPromptInjection(text: string): boolean {
  return detectPromptInjection(text).length > 0;
}

// ============================================================================
// Content Filtering
// ============================================================================

const BLOCKED_CONTENT = [
  { pattern: /\b(kill|murder|assassinate)\s+(someone|people|them)\b/i, category: 'violence' },
  { pattern: /\b(make|build|create)\s+a?\s*(bomb|explosive|weapon)\b/i, category: 'weapons' },
  { pattern: /\bhow\s+to\s+(hack|exploit|attack)\b/i, category: 'hacking' },
];

/**
 * Filter blocked content
 */
export function filterContent(text: string): {
  blocked: boolean;
  categories: string[];
  matches: string[];
} {
  const categories = new Set<string>();
  const matches: string[] = [];

  for (const { pattern, category } of BLOCKED_CONTENT) {
    const match = pattern.exec(text);
    if (match) {
      categories.add(category);
      matches.push(match[0]);
    }
  }

  return {
    blocked: categories.size > 0,
    categories: Array.from(categories),
    matches,
  };
}

// ============================================================================
// Output Validation
// ============================================================================

/**
 * Validate output against Zod schema
 */
export function validateOutput<T>(
  output: string,
  schema: z.ZodType<T>
): { valid: boolean; data?: T; error?: string } {
  try {
    // Try to parse as JSON first
    let parsed: any;
    try {
      parsed = JSON.parse(output);
    } catch {
      // If not JSON, use the raw string
      parsed = output;
    }

    const result = schema.safeParse(parsed);
    if (result.success) {
      return { valid: true, data: result.data };
    } else {
      return { valid: false, error: result.error.message };
    }
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Validation failed',
    };
  }
}

/**
 * Ensure output is valid JSON
 */
export function validateJSON(output: string): { valid: boolean; data?: any; error?: string } {
  try {
    const data = JSON.parse(output);
    return { valid: true, data };
  } catch (error) {
    return {
      valid: false,
      error: error instanceof Error ? error.message : 'Invalid JSON',
    };
  }
}

// ============================================================================
// Guardrail Chain
// ============================================================================

export class Guardrail {
  private config: GuardrailConfig;

  constructor(config: GuardrailConfig = {}) {
    this.config = config;
  }

  /**
   * Validate input text
   */
  validateInput(text: string): ValidationResult {
    const issues: ValidationIssue[] = [];

    // Check length
    if (this.config.maxLength && text.length > this.config.maxLength) {
      issues.push({
        type: 'length',
        severity: 'medium',
        message: `Input exceeds max length of ${this.config.maxLength}`,
      });
    }

    // Check PII
    if (this.config.detectPII !== false) {
      const piiFindings = detectPII(text);
      for (const finding of piiFindings) {
        issues.push({
          type: 'pii',
          severity: 'high',
          message: `Detected ${finding.type}`,
          position: finding.position,
          detected: finding.value,
        });
      }
    }

    // Check prompt injection
    if (this.config.detectPromptInjection !== false) {
      const injectionFindings = detectPromptInjection(text);
      for (const finding of injectionFindings) {
        issues.push({
          type: 'prompt_injection',
          severity: 'critical',
          message: `Possible prompt injection: ${finding.type}`,
          position: finding.position,
          detected: finding.matched,
        });
      }
    }

    // Check blocked content
    const contentFilter = filterContent(text);
    if (contentFilter.blocked) {
      for (const category of contentFilter.categories) {
        issues.push({
          type: 'blocked_content',
          severity: 'critical',
          message: `Blocked content category: ${category}`,
        });
      }
    }

    // Custom patterns
    if (this.config.customPatterns) {
      for (const { name, pattern, severity } of this.config.customPatterns) {
        const match = pattern.exec(text);
        if (match) {
          issues.push({
            type: 'custom',
            severity,
            message: `Matched custom pattern: ${name}`,
            position: { start: match.index, end: match.index + match[0].length },
            detected: match[0],
          });
        }
      }
    }

    const valid = !issues.some(i => i.severity === 'critical' || i.severity === 'high');

    return {
      valid,
      issues,
      sanitized: this.config.detectPII ? redactPII(text) : undefined,
    };
  }

  /**
   * Validate output text
   */
  validateOutput(text: string): ValidationResult {
    const issues: ValidationIssue[] = [];

    // Check PII in output
    if (this.config.detectPII !== false) {
      const piiFindings = detectPII(text);
      for (const finding of piiFindings) {
        issues.push({
          type: 'pii_leak',
          severity: 'high',
          message: `Output contains ${finding.type}`,
          position: finding.position,
        });
      }
    }

    const valid = !issues.some(i => i.severity === 'critical' || i.severity === 'high');

    return {
      valid,
      issues,
      sanitized: this.config.detectPII ? redactPII(text) : undefined,
    };
  }
}

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a guardrail with default config
 */
export function createGuardrail(config?: GuardrailConfig): Guardrail {
  return new Guardrail(config);
}

/**
 * Create a strict guardrail (all checks enabled)
 */
export function createStrictGuardrail(): Guardrail {
  return new Guardrail({
    detectPII: true,
    detectPromptInjection: true,
    maxLength: 10000,
  });
}

/**
 * Create a permissive guardrail (minimal checks)
 */
export function createPermissiveGuardrail(): Guardrail {
  return new Guardrail({
    detectPII: false,
    detectPromptInjection: true,
  });
}
