---
name: SAST Finding Triage (Jira, structured)
description: Triage a SAST finding from a Jira ticket using structured JSON output (rendered to Jira wiki markup server-side)
on:
  workflow_dispatch:
    inputs:
      jira_key:
        description: 'Jira ticket key (e.g. EPMMLSRDEM-78)'
        required: true
        type: string
permissions:
  contents: read
engine: claude
network:
  allowed:
    - defaults
    - jiraeu.epam.com
tools:
  edit:
  bash:
    - "grep"
    - "rg"
    - "find"
    - "ls"
    - "cat"
    - "head"
    - "tail"
    - "wc"
    - "sed"
    - "awk"
jobs:
  jira_fetch:
    runs-on: ubuntu-latest
    outputs:
      source_file: ${{ steps.parse.outputs.source_file }}
      source_line: ${{ steps.parse.outputs.source_line }}
      vuln_type: ${{ steps.parse.outputs.vuln_type }}
      jira_summary: ${{ steps.parse.outputs.jira_summary }}
      jira_issuetype: ${{ steps.parse.outputs.jira_issuetype }}
    steps:
      - name: Fetch and parse Jira ticket
        id: parse
        env:
          JIRA_URL: ${{ vars.JIRA_URL }}
          JIRA_PAT: ${{ secrets.JIRA_PAT }}
          JIRA_KEY: ${{ inputs.jira_key }}
        run: |
          set -euo pipefail

          if [ -z "${JIRA_URL:-}" ]; then
            echo "::error::Repository variable JIRA_URL is not set"
            exit 1
          fi
          if [ -z "${JIRA_PAT:-}" ]; then
            echo "::error::Repository secret JIRA_PAT is not set"
            exit 1
          fi

          # Strip any stray whitespace from JIRA_URL (paste-time newlines etc.)
          JIRA_URL="${JIRA_URL%/}"
          JIRA_URL="$(printf '%s' "$JIRA_URL" | tr -d '[:space:]')"
          echo "Resolved JIRA_URL=[$JIRA_URL]"
          echo "JIRA_KEY=[$JIRA_KEY]"

          response_file=$(mktemp)
          curl_stderr=$(mktemp)
          set +e
          http_code=$(curl -sS -o "$response_file" -w "%{http_code}" \
            --connect-timeout 15 --max-time 60 \
            -H "Authorization: Bearer $JIRA_PAT" \
            -H "Accept: application/json" \
            "$JIRA_URL/rest/api/2/issue/$JIRA_KEY" \
            2> "$curl_stderr")
          curl_rc=$?
          set -e

          if [ "$curl_rc" -ne 0 ]; then
            echo "::error::curl failed with exit code $curl_rc"
            echo "--- curl stderr ---"
            cat "$curl_stderr" || true
            exit 1
          fi

          if [ "$http_code" != "200" ]; then
            echo "::error::Jira returned HTTP $http_code for $JIRA_KEY"
            echo "--- response body (first 500 chars) ---"
            head -c 500 "$response_file" || true
            echo
            exit 1
          fi

          summary=$(jq -r '.fields.summary // ""' "$response_file")
          desc=$(jq -r '.fields.description // ""' "$response_file")
          issuetype=$(jq -r '.fields.issuetype.name // ""' "$response_file")

          # Jira description uses *bold* markup for labels and [text | url] for
          # links. Helper extracts a labeled field tolerantly:
          #   - asterisks around the label (`*Label*:` or `*Label:*`) are optional
          #   - whole rest of the line is captured (not just first whitespace token)
          #   - Jira link [text | url] is collapsed to just `text`
          extract_field() {
            local label="$1"
            printf '%s\n' "$desc" \
              | grep -m1 -E "\*?${label}\*?:\*?[[:space:]]*" \
              | sed -E "s/.*\*?${label}\*?:\*?[[:space:]]*//" \
              | sed -E 's/^\[[[:space:]]*//; s/[[:space:]]*\|.*//; s/\][[:space:]]*$//' \
              | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
          }

          source_file=$(extract_field 'Source File')
          source_line_raw=$(extract_field 'Source Line')
          source_line=$(printf '%s' "$source_line_raw" | grep -oE '[0-9]+' | head -1)

          rule_name=$(printf '%s\n' "$desc" \
            | grep -m1 -E '^[[:space:]-]*Rule short description:[[:space:]]*' \
            | sed -E 's/.*Rule short description:[[:space:]]*//; s/[[:space:]]+$//')
          if [ -z "$rule_name" ]; then
            rule_name=$(printf '%s\n' "$desc" \
              | grep -m1 -E '^[[:space:]-]*Rule name:[[:space:]]*' \
              | sed -E 's/.*Rule name:[[:space:]]*//; s/[[:space:]]+$//')
          fi
          if [ -z "$rule_name" ]; then
            rule_name="$summary"
          fi

          echo "DEBUG parsed:"
          echo "  source_file=[$source_file]"
          echo "  source_line=[$source_line]"
          echo "  rule_name=[$rule_name]"
          echo "  summary=[$summary]"
          echo "  issuetype=[$issuetype]"

          if [ -z "$source_file" ] || [ -z "$source_line" ]; then
            echo "::error::Could not parse Source File / Source Line from Jira description for $JIRA_KEY"
            echo "--- description (first 800 chars) ---"
            printf '%s' "$desc" | head -c 800
            echo
            exit 1
          fi

          {
            echo "source_file=$source_file"
            echo "source_line=$source_line"
            echo "vuln_type=$rule_name"
            echo "jira_summary=$summary"
            echo "jira_issuetype=$issuetype"
          } >> "$GITHUB_OUTPUT"

          # Write the full description to a file the agent will read directly.
          # Avoids embedding the description in the agent prompt.
          printf '%s\n' "$desc" > jira-description.txt

          echo "✅ Parsed Jira ticket $JIRA_KEY"
          echo "  source_file: $source_file"
          echo "  source_line: $source_line"
          echo "  vuln_type:   $rule_name"
          echo "  description bytes: $(wc -c < jira-description.txt)"
      - name: Upload Jira description artifact
        uses: actions/upload-artifact@v4
        with:
          name: jira-description
          path: jira-description.txt
          if-no-files-found: error
          retention-days: 1
  jira_post:
    runs-on: ubuntu-latest
    needs: [agent]
    if: always() && needs.agent.result == 'success'
    steps:
      - name: Checkout renderer script
        uses: actions/checkout@v4
        with:
          sparse-checkout: |
            .github/scripts
          sparse-checkout-cone-mode: false
      - name: Download triage-output artifact
        uses: actions/download-artifact@v4
        with:
          name: triage-output
          path: ./_artifacts
      - name: Render and post triage to Jira
        env:
          JIRA_URL: ${{ vars.JIRA_URL }}
          JIRA_PAT: ${{ secrets.JIRA_PAT }}
          JIRA_KEY: ${{ inputs.jira_key }}
          RUN_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
        run: |
          set -euo pipefail
          OUTPUT_FILE="./_artifacts/triage-output.json"
          RENDERER=".github/scripts/build-jira-comment.py"

          if [ ! -f "$OUTPUT_FILE" ]; then
            echo "::error::triage-output.json not found in downloaded artifact"
            find ./_artifacts -type f
            exit 1
          fi

          if ! jq empty "$OUTPUT_FILE" 2>/dev/null; then
            echo "::error::Agent output is not valid JSON"
            head -c 500 "$OUTPUT_FILE" || true
            exit 1
          fi

          decision=$(jq -r '.triage_decision // ""' "$OUTPUT_FILE")
          case "$decision" in
            "TRUE POSITIVE")  new_label="TRUE-POSITIVE-(AI-TRIAGE)" ;;
            "FALSE POSITIVE") new_label="FALSE-POSITIVE-(AI-TRIAGE)" ;;
            "UNCLEAR")        new_label="UNCLEAR-(AI-TRIAGE)" ;;
            *)
              echo "::error::Unknown or missing triage_decision in agent output: '$decision'"
              exit 1
              ;;
          esac

          comment_body=$(python3 "$RENDERER" "$OUTPUT_FILE" "$RUN_URL")
          if [ -z "$comment_body" ]; then
            echo "::error::Renderer produced empty output"
            exit 1
          fi

          label_payload=$(jq -n --arg new "$new_label" '{
            update: {
              labels: [
                {add: $new},
                {add: "ai-triaged"}
              ]
            }
          }')
          label_http=$(curl -sS -o /tmp/jira_label_resp -w "%{http_code}" -X PUT \
            -H "Authorization: Bearer $JIRA_PAT" \
            -H "Content-Type: application/json" \
            "$JIRA_URL/rest/api/2/issue/$JIRA_KEY" \
            -d "$label_payload")
          if [ "$label_http" != "204" ]; then
            echo "::error::Jira label update returned HTTP $label_http"
            head -c 500 /tmp/jira_label_resp || true
            exit 1
          fi

          comment_payload=$(jq -n --arg body "$comment_body" '{body: $body}')
          comment_http=$(curl -sS -o /tmp/jira_comment_resp -w "%{http_code}" -X POST \
            -H "Authorization: Bearer $JIRA_PAT" \
            -H "Content-Type: application/json" \
            "$JIRA_URL/rest/api/2/issue/$JIRA_KEY/comment" \
            -d "$comment_payload")
          if [ "$comment_http" != "201" ]; then
            echo "::error::Jira comment creation returned HTTP $comment_http"
            head -c 500 /tmp/jira_comment_resp || true
            exit 1
          fi

          echo "✅ Jira $JIRA_KEY updated with label $new_label and triage comment"
safe-outputs:
  noop:
pre-agent-steps:
  - name: Download Jira description artifact into workspace
    uses: actions/download-artifact@v4
    with:
      name: jira-description
      path: .
post-steps:
  - name: Upload triage-output.json as artifact
    if: always()
    uses: actions/upload-artifact@v4
    with:
      name: triage-output
      path: triage-output.json
      if-no-files-found: error
      retention-days: 7
timeout-minutes: 15
strict: true
---

# SAST Finding Triage (Jira-driven)

You are triaging a SAST finding tracked in Jira ticket **${{ inputs.jira_key }}** ("${{ needs.jira_fetch.outputs.jira_summary }}").

## Finding details (parsed from the Jira description)

- **vulnerability_type**: ${{ needs.jira_fetch.outputs.vuln_type }}
- **source_file**: ${{ needs.jira_fetch.outputs.source_file }}
- **source_line**: ${{ needs.jira_fetch.outputs.source_line }}
- **issue_type**: ${{ needs.jira_fetch.outputs.jira_issuetype }}

The full Jira description is in the file `jira-description.txt` at the workspace root. Read it once before starting the triage.

## Step 1 — Pick the right skill

Match `vulnerability_type` (case-insensitive) against these patterns and read **only** the matching skill's `SKILL.md`:

- Matches `ssrf` or `server.?side.?request.?forgery` → read `.github/skills/sast-triage-ssrf/SKILL.md`
- Otherwise matches any of `hardcoded`, `password`, `secret`, `credential`, `api.?key`, `token` → read `.github/skills/sast-triage-hardcoded-secrets/SKILL.md`
- Otherwise → read `.github/skills/sast-triage-general/SKILL.md`

Do not read the other two skills. Do not read any `references/output-template.md` files — the output schema for this workflow is defined in Step 3 below, not in the skill.

## Step 2 — Run the triage

Follow the chosen skill's analysis methodology exactly as written. In particular:

- Apply the MANDATORY RULE — Production Code Assumption.
- Read `source_file` directly. Include the surrounding context the skill calls for (typically 20–30 lines).
- Explore related files only when the skill instructs and only when they bear on the assessment.
- Make decisions per the skill's framework, citing concrete `file:line` evidence at every step.
- If `source_file` does not exist or the description is too sparse to verify, classify the triage as `UNCLEAR` rather than guess.

The skill defines *how to think*. The output schema in Step 3 defines *what to emit*. Use both.

## Step 3 — Emit structured JSON

Write a single JSON object to `triage-output.json` at the workflow workspace root. The schema below is the contract — the post-step renders these fields into a Jira comment using a deterministic template, so field names must match exactly.

The JSON object IS the entire file content — no wrapping keys, no markdown, no code fences around the JSON.

### Schema (general triager)

If you read `sast-triage-general/SKILL.md`, emit this shape:

```json
{
  "triager_type": "general",
  "triage_decision": "TRUE POSITIVE | FALSE POSITIVE | UNCLEAR",
  "category": "<see Category rules>",
  "additional_category": "<other FP reasons or N/A>",
  "confidence": "Low | Medium | High",
  "vulnerability_class": "<e.g. SSRF, XSS, XXE, Path Traversal, SQL Injection, Weak Cryptography, etc.>",
  "summary": "<one plain-language sentence stating the finding and verdict>",

  "code_snippet": "<3–5 lines of source as it appears in the file, with a leading // Line N-M comment>",
  "code_snippet_language": "<typescript | javascript | python | java | go | csharp | ...>",
  "code_location": "<file:line-range, e.g. routes/userProfile.ts:74-98>",
  "code_summary": "<one sentence describing what the code does>",

  "files_examined": ["<file paths examined during analysis>"],
  "search_description": "<brief note on identifiers, routes, callers traced>",

  "vulnerability_in_code": "TRUE | FALSE | UNCLEAR",
  "vulnerability_explanation": "<2–4 sentences citing file:line>",

  "impact_assessment": "TRUE | FALSE | UNCLEAR | N/A",
  "impact_explanation": "<2–4 sentences; empty string if N/A>",

  "exploitable_assessment": "TRUE | FALSE | UNCLEAR | N/A",
  "exploitable_explanation": "<2–4 sentences; empty string if N/A>",

  "is_taint_flow_vuln": true,
  "external_input": "TRUE | FALSE | UNCLEAR | <empty if config issue or N/A>",
  "trust_level": "Untrusted | Trusted (non-human) | Trusted (DevOps) | Privileged (human) | UNCLEAR | <empty>",
  "taint_flow": "Viable | Blocked (explicit) | Blocked (implicit) | UNCLEAR | <empty>",
  "sink_usage": "Dangerous | Secure API | Secure Config | Benign Use | UNCLEAR | <empty>",

  "compensatory_controls": "<description of partial mitigations, or N/A>",
  "key_facts": ["<3–8 declarative sentences, each citing concrete evidence>"],
  "manual_review_points": ["<empty array unless triage_decision == UNCLEAR>"],
  "additional_observations": ["<empty array unless an insight does not fit any other field>"]
}
```

### Schema (hardcoded-secrets / password triager)

If you read `sast-triage-hardcoded-secrets/SKILL.md`, emit this shape:

```json
{
  "triager_type": "password",
  "triage_decision": "TRUE POSITIVE | FALSE POSITIVE",
  "category": "<see Category rules>",
  "confidence": "Low | Medium | High",
  "vulnerability_class": "Hardcoded Secret | Hardcoded Password | Hardcoded API Key | Hardcoded Token",
  "summary": "<one plain-language sentence>",

  "code_snippet": "<3–5 lines with all sensitive values redacted per the skill's rules, with a leading // Line N-M comment>",
  "code_snippet_language": "<language>",
  "code_location": "<file:line-range>",
  "code_summary": "<one sentence>",

  "files_examined": ["<paths>"],
  "search_description": "<brief note>",

  "flagged_value": "<the flagged credential value, redacted>",
  "pattern": "<what the value looks like — e.g. high-entropy password, AWS key pattern, Base64 string>",
  "context": "<file type, location, surrounding code with values redacted>",

  "is_test_environment": false,
  "is_encrypted": false,
  "encryption_details": "<config details if encrypted, else empty string>",
  "is_fallback_default": false,
  "fallback_pattern": "<the pattern if fallback default, else empty string>",

  "risk_reduction_factors": ["<each factor as a sentence with technical evidence; empty array if none>"],
  "analysis_explanation": "<2–4 sentences using only redacted values>",
  "key_facts": ["<critical evidence sentences>"],
  "additional_observations": []
}
```

### Schema (SSRF triager)

If you read `sast-triage-ssrf/SKILL.md`, emit this shape:

```json
{
  "triager_type": "ssrf",
  "triage_decision": "TRUE POSITIVE | FALSE POSITIVE | UNCLEAR",
  "category": "<see Category rules>",
  "confidence": "Low | Medium | High",
  "vulnerability_class": "SSRF",
  "summary": "<one plain-language sentence>",

  "code_snippet": "<3–5 lines with leading // Line N-M comment>",
  "code_snippet_language": "<language>",
  "code_location": "<file:line-range>",
  "code_summary": "<one sentence>",

  "files_examined": ["<paths>"],
  "search_description": "<brief note>",

  "ssrf_pattern_present": "TRUE | FALSE",
  "ssrf_pattern_explanation": "<cite specific code (method, line, variable) showing the outbound request and attacker-controlled input>",

  "is_test_code": false,
  "is_test_code_explanation": "<cite file path, test framework, or state production code>",

  "host_control": "TRUE | FALSE | N/A",
  "host_control_explanation": "<empty string if N/A>",
  "host_control_mitigations": "TRUE | FALSE | N/A",
  "host_control_mitigations_explanation": "<empty string if N/A>",

  "path_control": "TRUE | FALSE | N/A",
  "path_control_explanation": "<empty string if N/A>",
  "path_control_mitigations": "TRUE | FALSE | N/A",
  "path_control_mitigations_explanation": "<empty string if N/A>",
  "redirect_to_hostile": "TRUE | FALSE | N/A",
  "redirect_to_hostile_explanation": "<empty string if N/A>",

  "query_control": "TRUE | FALSE | N/A",
  "query_control_explanation": "<empty string if N/A>",
  "host_escalation": "TRUE | FALSE | N/A",
  "host_escalation_explanation": "<empty string if N/A>",

  "analysis_summary": "<2–4 sentences tying answers to the verdict>",
  "key_facts": ["<critical evidence>"],
  "additional_observations": []
}
```

### Common rules

- **All fields are required.** Use `"N/A"` for strings, `[]` for arrays, `false` for booleans rather than omitting keys.
- **`triage_decision`** uses the spaced form: `TRUE POSITIVE`, `FALSE POSITIVE`, `UNCLEAR`. No underscores.
- **`category`** rules:
  - `TRUE POSITIVE` or `UNCLEAR` → `"N/A"`
  - `FALSE POSITIVE` (general) → one of: `FP - NOISE:NotSecret`, `FP - NOISE:NotSensitiveDataLeak`, `FP - NOISE:Mismatch`, `FP - TRIVIAL:TestCode`, `FP - TRIVIAL:NotInProd`, `FP - TRIVIAL:NoRiskToCase`, `FP - TRIVIAL:NoRiskToModule`, `FP - THEORETICAL:NoExternalInput`, `FP - THEORETICAL:TrustedExternalNonhumanInput`, `FP - THEORETICAL:DevOpsCode`, `FP - THEORETICAL:TaintFlowNotFeasible`, `FP - THEORETICAL:BenignUse`, `FP - MITIGATED:InputValidation`, `FP - MITIGATED:SecureCode`, `FP - MITIGATED:SecureConfig`, `FP - MITIGATED:ApprovedCompensatingControl`, `FP - OTHERS`
  - For `password`: `POTENTIALLY SENSITIVE (TEST CODE)`, `POTENTIALLY SENSITIVE (ENCRYPTED)`, `POTENTIALLY SENSITIVE (FALLBACK DEFAULT)`, `POTENTIALLY SENSITIVE (OTHER)`, or `N/A`.
  - For `ssrf`: `PATH TRAVERSAL`, `HOST CONTROL`, `OPEN REDIRECT` (TP) or `QUERY PARAMETER`, `MITIGATED`, `MISMATCH`, `TEST CODE` (FP).
- **`code_snippet`** must be real source from the file (verbatim), not paraphrased. Include a leading line-comment indicating line numbers (e.g. `// Line 74-98`).
- **`is_taint_flow_vuln`** (general only) — `true` for injection / taint-flow vulns; `false` for configuration/design issues (weak crypto, missing headers, hardcoded secrets, insecure randomness, TLS issues). When `false`, set the four taint-flow fields (`external_input`, `trust_level`, `taint_flow`, `sink_usage`) to empty strings and put the verdict explanation in `exploitable_explanation`.
- **Stage gating** (general) — when `vulnerability_in_code` is `FALSE` or `UNCLEAR`, set `impact_assessment` and `exploitable_assessment` to `"N/A"` and their explanations to empty strings.
- **`additional_observations`** is an escape hatch for insights that do not fit any other schema field. Use sparingly — most triages should leave this as `[]`.

After writing the JSON file, call `noop` with a one-sentence summary. The file at `triage-output.json` will be picked up automatically by the downstream Jira-posting job — you do not need to upload it.

## Constraints

- Do not modify any files in the checked-out repository. Your only file write is `triage-output.json`.
- Do not invent file paths or line numbers. If a path you were given does not exist, set `triage_decision` to `UNCLEAR` and explain in `vulnerability_explanation` (or `analysis_summary` for SSRF / `analysis_explanation` for password).
- Do not access the network. The repository plus the parsed Jira fields are everything you need.
