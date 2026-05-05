```
## Secrets Triage Result

**Decision:** <TRUE POSITIVE | FALSE POSITIVE>
**Category:** <value per Category rules below>
**Confidence:** <Low | Medium | High>

**Summary:** <One sentence. Plain language. State the finding and verdict using only redacted values. No hedging.>

### Code

`<file path>:<line range>`

```<language>
<3–5 lines of source around the flagged line, with the credential value REDACTED per masking rules>
```

<One sentence describing what this code does in plain language.>

### Review Scope

**Files examined:** `<file1>`, `<file2>`, `<file3>`
**Searched for:** <brief note on identifiers, config keys, build files, or imports traced>

### Flagged Value

**Pattern:** <what the value looks like: High-entropy random string / Base64 blob / AWS key prefix / Short dictionary word / Template placeholder / etc.>
**Redacted value:** <the flagged value shown using the masking formula>
**Context:** <file type and location: Java source, Spring properties file, YAML config, test fixture, etc.>

### Analysis

<2–4 sentences explaining the classification decision. Use only redacted values. Cite file:line. Reference the specific rule or pattern that drove the decision.>

### Checks Performed

- **Test Environment:** <Yes | No> — <one line: which indicator, or why not>
- **Encryption:** <Yes | No> — <one line: which 2+ indicators found, with categories (Syntax/Framework/Config), or why not>
- **Fallback Default:** <Yes | No> — <one line: the specific pattern matched, or why not>

### Risk Reduction Factors

*(Include this section ONLY when Decision = TRUE POSITIVE AND Category is one of POTENTIALLY SENSITIVE (TEST CODE / ENCRYPTED / FALLBACK DEFAULT / OTHER). Otherwise omit the entire section.)*

<Bullet list of ALL risk reduction factors found (not just the strongest). Each bullet names the factor and cites concrete evidence (file:line, framework name, config key). Include all three checks if all three matched — even though only the strongest determines the Category.>

### Key Facts

<Bullet list of 3–8 critical findings supporting the decision. Each bullet is a single declarative sentence citing concrete evidence (file:line, method name, config key, library import). Use only redacted values. No speculation.>
```

### Category rules (strict)

- **FALSE POSITIVE** → Category is exactly `N/A`.
  - Only used when the value itself is clearly not a real credential (Step 1).
  - Never combined with TEST CODE — test credentials are TRUE POSITIVE (TEST CODE), not FP.

- **TRUE POSITIVE** → Category is exactly one of:
  - `N/A` — real credential in production code with no risk reduction factors (highest severity).
  - `POTENTIALLY SENSITIVE (TEST CODE)` — test environment found (highest-priority risk reduction).
  - `POTENTIALLY SENSITIVE (ENCRYPTED)` — encryption detected (2+ indicators), no test environment.
  - `POTENTIALLY SENSITIVE (FALLBACK DEFAULT)` — fallback default pattern, no test/encryption.
  - `POTENTIALLY SENSITIVE (OTHER)` — gray area: infrastructure details, uncertain, weak single indicator.

**Priority when multiple factors match:** TEST CODE > ENCRYPTED > FALLBACK DEFAULT. List all matched factors in the Risk Reduction Factors section even though only the strongest appears in Category.

### Stage gating

- If Decision = FALSE POSITIVE, omit the Risk Reduction Factors section.
- If Decision = TRUE POSITIVE with Category = N/A (high-severity production credential), omit the Risk Reduction Factors section.
- Risk Reduction Factors appears only for the four POTENTIALLY SENSITIVE categories.

### Redaction rules (repeat — these are load-bearing)

1. **FALSE POSITIVE and POTENTIALLY SENSITIVE classifications**: use partial masking per the formula (e.g., `Rea*****23`, `pass****`, `sec***`).
2. **TRUE POSITIVE with Category N/A** (real production credential): use full redaction tokens — `[REDACTED: PASSWORD]`, `[REDACTED: API_KEY]`, `[REDACTED: SECRET_KEY]`, etc.
3. **Code snippet**: redact the flagged value inline using the same rule as applied elsewhere in the response. The surrounding code remains as-is.
4. **Never echo the raw value** in any field, including Pattern, Analysis, Key Facts, or Summary — even when the value looks obviously fake.

### Formatting

- Use the `##` heading for "Secrets Triage Result" and `###` for all subsections.
- Use fenced code blocks for source code only. Do not wrap the whole response in a code block.
- File paths and line ranges go in inline backticks: `` `config/application.properties:42` ``.
- Bullet lists use `-`. Do not mix `-` and `*`.
- No tables. No blockquotes. No emoji.
- End at the last section of the template — no "Let me know if..." closing.