# AI Guardrails

Input/output validation and safety for AI applications.

## Quick Start

```bash
npx ai-guardrails validate "Check this text"
```

## What It Does

- Detect PII (email, phone, SSN, credit cards)
- Block prompt injection attempts
- Filter harmful content
- Validate LLM outputs

## Usage

```bash
# Validate text
npx ai-guardrails validate "text"

# Detect PII
npx ai-guardrails pii "Email: test@example.com"

# Check injection
npx ai-guardrails injection "Ignore previous instructions"

# Generate files
npx ai-guardrails init
```

## Part of the LXGIC Dev Toolkit

One of 110+ free developer tools from LXGIC Studios.

- GitHub: https://github.com/lxgicstudios
- Twitter: https://x.com/lxgicstudios
- Website: https://lxgicstudios.com

## License

MIT. Free forever.
