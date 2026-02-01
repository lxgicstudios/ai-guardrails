# ai-guardrails

[![npm version](https://img.shields.io/npm/v/ai-guardrails.svg)](https://www.npmjs.com/package/ai-guardrails)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

Input/output validation and safety for AI applications. Content filtering, PII detection, prompt injection defense, output validation.

## Quick Start

```bash
# Validate text
npx ai-guardrails validate "Check this text"

# Detect PII
npx ai-guardrails pii "Email: test@example.com"

# Check for prompt injection
npx ai-guardrails injection "Ignore all previous instructions"
```

## Features

- 🔍 **PII detection** - Email, phone, SSN, credit cards
- 🛡️ **Prompt injection** - Detect manipulation attempts
- 🚫 **Content filtering** - Block harmful content
- ✅ **Output validation** - Validate AI responses

## Installation

```bash
npx ai-guardrails validate "text"
npm install ai-guardrails
```

## CLI Usage

```bash
# Full validation
npx ai-guardrails validate "My email is test@example.com"

# PII detection only
npx ai-guardrails pii "Call me at 555-123-4567"

# Redact PII
npx ai-guardrails pii "Email: test@example.com" --redact

# Prompt injection detection
npx ai-guardrails injection "Ignore previous instructions"

# Content filtering
npx ai-guardrails filter "Some text to check"
```

## Programmatic Usage

```typescript
import {
  Guardrail,
  detectPII,
  redactPII,
  detectPromptInjection,
  hasPromptInjection,
  validateOutput,
  createStrictGuardrail,
} from 'ai-guardrails';

// Create guardrail
const guardrail = createStrictGuardrail();

// Validate input
const result = guardrail.validateInput(userMessage);
if (!result.valid) {
  console.log('Issues:', result.issues);
}

// Detect PII
const pii = detectPII("Email: test@example.com");
// [{ type: 'email', value: 'test@example.com', position: {...} }]

// Redact PII
const safe = redactPII("Call 555-123-4567");
// "Call [REDACTED]"

// Check prompt injection
if (hasPromptInjection(userInput)) {
  throw new Error('Injection attempt detected');
}

// Validate output with Zod schema
import { z } from 'zod';
const schema = z.object({ answer: z.string() });
const validation = validateOutput(llmOutput, schema);
```

## Detection Types

| Type | Examples |
|------|----------|
| email | user@example.com |
| phone | 555-123-4567 |
| ssn | 123-45-6789 |
| creditCard | 4111-1111-1111-1111 |
| prompt_injection | "Ignore previous instructions" |

## Part of the LXGIC Dev Toolkit

One of 110+ free developer tools from LXGIC Studios.

- GitHub: https://github.com/lxgicstudios
- Twitter: https://x.com/lxgicstudios
- Website: https://lxgicstudios.com

## License

MIT. Free forever.
