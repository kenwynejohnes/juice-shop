## Triage Result

**Decision:** <TRUE POSITIVE | FALSE POSITIVE | UNCLEAR>
**Category:** <value per Category rules below>
**Confidence:** <Low | Medium | High>
**Vulnerability Class:** <e.g. SSRF, XSS, XXE, Path Traversal, Hardcoded Secret, SQL Injection, Weak Cryptography, Insecure Deserialization, etc.>

**Summary:** <One sentence. Plain language. State the finding and verdict. No hedging.>

### Code

`<file path>:<line range>`

```<language>
<3–5 lines of vulnerable source as it appears in the file>
```

<One sentence describing what this code does in plain language.>

### Review Scope

**Files examined:** `<file1>`, `<file2>`, `<file3>`
**Searched for:** <brief note on identifiers, routes, or callers traced>

### Stage 1 — Vulnerability Verification

**Vulnerability in Code:** <TRUE | FALSE | UNCLEAR>

<2–4 sentences citing file:line and specific symbols. If FALSE, name the NOISE subcategory (NotSecret / NotSensitiveDataLeak / Mismatch). If UNCLEAR, state why.>

### Stage 2 — Impact Assessment

*(Include this section only if Stage 1 = TRUE. Otherwise omit it entirely — do not include it with placeholders.)*

**Impact:** <TRUE | FALSE | UNCLEAR>

<2–4 sentences. Apply the production code assumption. If FALSE, name the TRIVIAL subcategory (TestCode / NotInProd / NoRiskToCase / NoRiskToModule).>

### Stage 3 — Reachability Assessment

*(Include this section only if Stage 1 = TRUE. Otherwise omit it entirely.)*

**Exploitable:** <TRUE | FALSE | UNCLEAR>

*(If the finding is a Configuration/Design vulnerability where presence equals exploitability — weak crypto, missing headers, hardcoded secrets, insecure randomness, TLS issues, etc. — write exactly: `TRUE (Configuration/Design Issue — presence equals exploitability)` and skip the four sub-fields below.)*

- **External Input:** <TRUE | FALSE | UNCLEAR> — <one line: where input enters>
- **Trust Level:** <Untrusted | Trusted (non-human) | Trusted (DevOps) | Privileged (human) | UNCLEAR> — <one line: source type>
- **Taint Flow:** <Viable | Blocked (explicit) | Blocked (implicit) | UNCLEAR> — <one line: what happens in transit>
- **Sink Usage:** <Dangerous | Secure API | Secure Config | Benign Use | UNCLEAR> — <one line: how the sink uses the data>

### Primary FP Reason

<The first FP reason discovered in this run (CATEGORY:Subcategory format), or `N/A` for TRUE POSITIVE and UNCLEAR.>

### Additional FP Reasons

<Bullet list of other FP reasons found, each in CATEGORY:Subcategory format, or `None`.>

### Compensating Controls Found

<Bullet list of compensating controls (PrivilegedExternalHumanInput, QuestionableInputValidation, CompensatingControl, or named controls like "Content Security Policy", "rate limiting"). Each bullet names the control and why it only reduces rather than eliminates risk. `None` if none found.>

### Key Facts

<Bullet list of 3–8 critical findings. Each bullet is a single declarative sentence citing concrete evidence (file:line, method name, variable name, configuration value). No speculation.>

### Points Requiring Manual Review

*(Include this section only if Decision = UNCLEAR. Otherwise omit it.)*

<Bullet list of 1–4 specific questions a human reviewer should answer to resolve the ambiguity.>
```

### Category rules (strict)

- **TRUE POSITIVE** → Category is `N/A`
- **UNCLEAR** → Category is `N/A`
- **FALSE POSITIVE** → Category is one of:
  - `FP - NOISE:NotSecret` | `FP - NOISE:NotSensitiveDataLeak` | `FP - NOISE:Mismatch`
  - `FP - TRIVIAL:TestCode` | `FP - TRIVIAL:NotInProd` | `FP - TRIVIAL:NoRiskToCase` | `FP - TRIVIAL:NoRiskToModule`
  - `FP - THEORETICAL:NoExternalInput` | `FP - THEORETICAL:TrustedExternalNonhumanInput` | `FP - THEORETICAL:DevOpsCode` | `FP - THEORETICAL:TaintFlowNotFeasible` | `FP - THEORETICAL:BenignUse`
  - `FP - MITIGATED:InputValidation` | `FP - MITIGATED:SecureCode` | `FP - MITIGATED:SecureConfig` | `FP - MITIGATED:ApprovedCompensatingControl`
  - `FP - OTHERS` (last resort)

Never write `N/A` as "Not Available", "None", "n/a", or any other variant.
Never place `PrivilegedExternalHumanInput`, `QuestionableInputValidation`, or `CompensatingControl` in the Category field. Those belong only in the Compensating Controls Found section.

### Stage gating

- Stage 1 = FALSE or UNCLEAR → omit the Stage 2 and Stage 3 sections entirely. Do not write them with "N/A" placeholders.
- Stage 1 = TRUE → always include both Stage 2 and Stage 3, regardless of Stage 2 outcome.
- If the finding is a Configuration/Design vulnerability, include the Stage 3 section with the full "presence equals exploitability" note, and omit the four External Input / Trust Level / Taint Flow / Sink Usage bullets.

### Formatting

- Use the `##` heading for "Triage Result" and `###` for all subsections.
- Use fenced code blocks for source code only. Do not wrap the whole response in a code block.
- File paths and line ranges go in inline backticks: `` `routes/userProfile.ts:74-98` ``.
- Bullet lists use `-`. Do not mix `-` and `*`.
- No tables. No blockquotes. No emoji.
- No trailing "If you want to dig deeper..." or "Would you like me to..." invitations. End at the last section of the template.