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
engine: copilot
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
    permissions:
      contents: read
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
                {add: $new}
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
  threat-detection: false
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

Match `vulnerability_type` (case-insensitive) against these patterns. For the **single matching skill**, read **both** files in its directory (`SKILL.md` and `output-schema.json`):

- Matches `ssrf` or `server.?side.?request.?forgery` → read `.github/skills/sast-triage-ssrf/SKILL.md` and `.github/skills/sast-triage-ssrf/output-schema.json`
- Otherwise matches any of `hardcoded`, `password`, `secret`, `credential`, `api.?key`, `token` → read `.github/skills/sast-triage-hardcoded-secrets/SKILL.md` and `.github/skills/sast-triage-hardcoded-secrets/output-schema.json`
- Otherwise → read `.github/skills/sast-triage-general/SKILL.md` and `.github/skills/sast-triage-general/output-schema.json`

Do not read the other two skills' files.

## Step 2 — Run the triage

Follow the chosen skill's analysis methodology exactly as written. In particular:

- Apply the MANDATORY RULE — Production Code Assumption.
- Read `source_file` directly. Include the surrounding context the skill calls for (typically 20–30 lines).
- Explore related files only when the skill instructs and only when they bear on the assessment.
- Make decisions per the skill's framework, citing concrete `file:line` evidence at every step.
- If `source_file` does not exist or the description is too sparse to verify, classify the triage as `UNCLEAR` rather than guess.

The skill defines *how to think*. The schema you read in Step 1 defines *what to emit*.

## Step 3 — Emit structured JSON

Write a single JSON object to `triage-output.json` at the workflow workspace root. Its shape must match the `output-schema.json` you read in Step 1 — same field names, same data types. Replace each placeholder string (e.g. `"<one sentence describing what the code does>"`) with your actual content for that finding.

The JSON object IS the entire file content — no wrapping keys, no markdown, no code fences around the JSON. Do not include the `_description` key from the schema (it is metadata about the schema, not part of the output).

### Common rules across all schemas

- **All schema fields are required.** Use `"N/A"` for strings, `[]` for arrays, `false` for booleans rather than omitting keys.
- **`triage_decision`** uses the spaced form: `TRUE POSITIVE`, `FALSE POSITIVE`, `UNCLEAR`. No underscores.
- **`code_snippet`** must be real source from the file (verbatim), not paraphrased. Include a leading line-comment indicating line numbers (e.g. `// Line 74-98`).
- **`additional_observations`** is an escape hatch for insights that do not fit any other schema field. Use sparingly — most triages should leave this as `[]`.
- **Stage gating** (general triager) — when `vulnerability_in_code` is `FALSE` or `UNCLEAR`, set `impact_assessment` and `exploitable_assessment` to `"N/A"` and their explanations to empty strings.
- **`is_taint_flow_vuln`** (general triager) — `true` for injection / taint-flow vulns; `false` for configuration/design issues (weak crypto, missing headers, hardcoded secrets, insecure randomness, TLS issues). When `false`, set the four taint-flow fields (`external_input`, `trust_level`, `taint_flow`, `sink_usage`) to empty strings and put the verdict explanation in `exploitable_explanation`.

The chosen skill's `SKILL.md` defines per-triager `category` rules and any other domain-specific constraints — refer there for allowed values.

After writing the JSON file, call `noop` with a one-sentence summary. The file at `triage-output.json` will be picked up automatically by the downstream Jira-posting job — you do not need to upload it.

## Constraints

- Do not modify any files in the checked-out repository. Your only file write is `triage-output.json`.
- Do not invent file paths or line numbers. If a path you were given does not exist, set `triage_decision` to `UNCLEAR` and explain in `vulnerability_explanation` (or `analysis_summary` for SSRF / `analysis_explanation` for password).
- Do not access the network. The repository plus the parsed Jira fields are everything you need.
