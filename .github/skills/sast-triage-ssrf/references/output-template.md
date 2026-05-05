```
## SSRF Triage Result

**Decision:** <TRUE POSITIVE | FALSE POSITIVE | UNCLEAR>
**Category:** <value per Category rules below>
**Confidence:** <Low | Medium | High>

**Summary:** <One sentence. Plain language. State the finding and verdict. No hedging.>

### Code

`<file path>:<line range>`

```<language>
<3–5 lines of vulnerable source as it appears in the file>
```

<One sentence describing what this code does in plain language.>

### Review Scope

**Files examined:** `<file1>`, `<file2>`, `<file3>`
**Searched for:** <brief note on identifiers, routes, callers, or config files traced>

### SSRF Pattern Analysis

**SSRF Pattern Present:** <TRUE | FALSE>

<2–4 sentences citing file:line. Reference the outbound HTTP call, the attacker-controlled variable, and how it reaches the URL. If FALSE, state why (no outbound request, no user input in URL, body-only usage, etc.) and skip the remaining sub-sections.>

**Test Code:** <Yes | No>

<One sentence. Cite the file path, test framework, or state it is production code.>

### URL Component Analysis

*(Include this section only if SSRF Pattern Present = TRUE and Test Code = No. Otherwise omit it.)*

**Host / Full URL Control:** <TRUE | FALSE | N/A>

<One sentence explaining what the attacker controls at the host/protocol/port level, or why they don't.>

**Host Control Mitigations:** <TRUE | FALSE | N/A>

*(N/A if Host Control is not TRUE.)*

<One sentence describing allowlists, validators, or their absence.>

**Path Segment Control:** <TRUE | FALSE | N/A>

*(N/A if Host Control is TRUE, since host dominates.)*

<One sentence explaining the concatenation pattern, position (trailing/sandwiched/placeholder), and how input reaches the path.>

**Path Control Mitigations:** <TRUE | FALSE | N/A>

*(N/A if Path Segment Control is not TRUE. URL encoding is NOT a mitigation.)*

<One sentence describing input validation, safe APIs, or their absence.>

**Redirect to Hostile Host:** <TRUE | FALSE | N/A>

*(N/A if Path Segment Control is not TRUE.)*

<One sentence explaining whether the path control can escalate via open redirect.>

**Query Parameter Control:** <TRUE | FALSE | N/A>

*(N/A if Host or Path control was found.)*

<One sentence explaining what query parameters the attacker controls.>

**Host Escalation via Query:** <TRUE | FALSE | N/A>

*(N/A if Query Parameter Control is not TRUE.)*

<One sentence explaining whether the query parameter can influence the destination host.>

### Analysis Summary

<2–4 sentences tying the findings above to the final classification. Explicitly reference which Option (1/2/3) drove the verdict.>

### Key Facts

<Bullet list of 3–8 critical findings. Each bullet is a single declarative sentence citing concrete evidence (file:line, method name, variable name, or specific configuration). No speculation.>
```

### Category rules (strict)

- **TRUE POSITIVE** → Category is exactly one of:
  - `Path Traversal` — attacker controls path segments on a fixed host (default TP category).
  - `Host Control` — attacker controls host/protocol/port/full URL.
  - `Open Redirect` — attacker can escalate to host control via redirect pattern.

- **FALSE POSITIVE** → Category is exactly one of:
  - `Query Parameter` — attacker input affects query only, no host/protocol/path influence.
  - `Mitigated` — SSRF vector exists but effective mitigation blocks exploitation.
  - `Mismatch` — no SSRF pattern (no outbound request, no user input in URL, or body-only).
  - `Test Code` — finding is in test code.

- **UNCLEAR** → Category is `N/A`.

**Forbidden combinations:**
- Never use `Query Parameter` with TRUE POSITIVE. Query-only findings are always FP.
- Never invent categories outside the lists above. If none fit, the Decision should be UNCLEAR with Category `N/A`.

### Stage gating

- If SSRF Pattern Present = FALSE → Decision is `FALSE POSITIVE`, Category is `Mismatch`. Omit the URL Component Analysis section.
- If Test Code = Yes → Decision is `FALSE POSITIVE`, Category is `Test Code`. Omit the URL Component Analysis section.
- Options evaluate in strict order: Host → Path → Query. Once a component is confirmed attacker-controlled, sub-components below it become `N/A`.

### Formatting

- Use the `##` heading for "SSRF Triage Result" and `###` for all subsections.
- Use fenced code blocks for source code only. Do not wrap the whole response in a code block.
- File paths and line ranges go in inline backticks: `` `src/services/ProductService.java:142-155` ``.
- Bullet lists use `-`. Do not mix `-` and `*`.
- No tables. No blockquotes. No emoji.
- End at the last section of the template — no "Let me know if..." closing.