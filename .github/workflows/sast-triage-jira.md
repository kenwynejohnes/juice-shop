---
description: Triage a SAST finding sourced from a Jira ticket; post the verdict back as a comment and label
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
      vuln_desc_b64: ${{ steps.parse.outputs.vuln_desc_b64 }}
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

          source_file=$(printf '%s' "$desc" | grep -oE 'Source File:[[:space:]]*[^[:space:]]+' | head -1 | sed -E 's/^Source File:[[:space:]]*//')
          source_line=$(printf '%s' "$desc" | grep -oE 'Source Line:[[:space:]]*[0-9]+' | head -1 | sed -E 's/^Source Line:[[:space:]]*//')
          rule_name=$(printf '%s' "$desc" | grep -m1 -oE 'Rule short description:[^\n]+' | sed -E 's/^Rule short description:[[:space:]]*//')
          if [ -z "$rule_name" ]; then
            rule_name=$(printf '%s' "$desc" | grep -m1 -oE 'Rule name:[^\n]+' | sed -E 's/^Rule name:[[:space:]]*//')
          fi
          if [ -z "$rule_name" ]; then
            rule_name="$summary"
          fi

          if [ -z "$source_file" ] || [ -z "$source_line" ]; then
            echo "::error::Could not parse Source File / Source Line from Jira description for $JIRA_KEY"
            echo "--- description (first 800 chars) ---"
            printf '%s' "$desc" | head -c 800
            echo
            exit 1
          fi

          vuln_desc_b64=$(printf '%s' "$desc" | base64 -w 0 2>/dev/null || printf '%s' "$desc" | base64 | tr -d '\n')

          {
            echo "source_file=$source_file"
            echo "source_line=$source_line"
            echo "vuln_type=$rule_name"
            echo "jira_summary=$summary"
            echo "jira_issuetype=$issuetype"
            echo "vuln_desc_b64=$vuln_desc_b64"
          } >> "$GITHUB_OUTPUT"

          echo "✅ Parsed Jira ticket $JIRA_KEY"
          echo "  source_file: $source_file"
          echo "  source_line: $source_line"
          echo "  vuln_type:   $rule_name"
safe-outputs:
  noop:
  upload-asset:
    allowed-exts: [".json"]
    max-size: 1024
  jobs:
    jira_post:
      runs-on: ubuntu-latest
      needs: [agent]
      if: always() && needs.agent.result == 'success'
      steps:
        - name: Download triage output artifact
          uses: actions/download-artifact@v4
          with:
            pattern: "*triage-output*"
            path: ./_artifacts
            merge-multiple: true

        - name: Locate triage-output.json
          id: locate
          run: |
            set -euo pipefail
            output_file=$(find ./_artifacts -type f -name 'triage-output.json' | head -1)
            if [ -z "$output_file" ]; then
              echo "::error::triage-output.json not found in agent artifacts"
              find ./_artifacts -type f
              exit 1
            fi
            echo "output_file=$output_file" >> "$GITHUB_OUTPUT"

        - name: Post triage to Jira
          env:
            JIRA_URL: ${{ vars.JIRA_URL }}
            JIRA_PAT: ${{ secrets.JIRA_PAT }}
            JIRA_KEY: ${{ inputs.jira_key }}
            RUN_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
            OUTPUT_FILE: ${{ steps.locate.outputs.output_file }}
          run: |
            set -euo pipefail

            if ! jq empty "$OUTPUT_FILE" 2>/dev/null; then
              echo "::error::Agent output is not valid JSON"
              head -c 500 "$OUTPUT_FILE" || true
              exit 1
            fi

            verdict=$(jq -r '.verdict // ""' "$OUTPUT_FILE")
            comment=$(jq -r '.comment_markdown // ""' "$OUTPUT_FILE")

            case "$verdict" in
              TRUE_POSITIVE)  new_label="TRUE-POSITIVE-(AI-TRIAGE)" ;;
              FALSE_POSITIVE) new_label="FALSE-POSITIVE-(AI-TRIAGE)" ;;
              UNCLEAR)        new_label="UNCLEAR-(AI-TRIAGE)" ;;
              *)
                echo "::error::Unknown or missing verdict in agent output: '$verdict'"
                exit 1
                ;;
            esac

            if [ -z "$comment" ]; then
              echo "::error::Agent output has empty comment_markdown"
              exit 1
            fi

            footer=$(printf '\n\n----\n_Posted by [SAST Triage workflow](%s) — verdict: %s_' "$RUN_URL" "$verdict")
            full_comment="$comment$footer"

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

            comment_payload=$(jq -n --arg body "$full_comment" '{body: $body}')
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

The full Jira description is provided as a base64-encoded blob below. Decode it before reading. (Encoding is used to safely pass multiline text through GitHub Actions outputs.)

```
${{ needs.jira_fetch.outputs.vuln_desc_b64 }}
```

To decode, you can use bash: `echo "<blob>" | base64 -d`. Or just read the description as-is — base64 of plain ASCII is recoverable by inspection if needed, but decoding is preferred.

## Step 1 — Pick the right skill

Match `vulnerability_type` (case-insensitive) against these patterns and read **only** the matching skill:

- Matches `ssrf` or `server.?side.?request.?forgery` → read `.github/skills/sast-triage-ssrf/SKILL.md`
- Otherwise matches any of `hardcoded`, `password`, `secret`, `credential`, `api.?key`, `token` → read `.github/skills/sast-triage-hardcoded-secrets/SKILL.md`
- Otherwise → read `.github/skills/sast-triage-general/SKILL.md`

Then read the `references/output-template.md` file under that same skill directory.

Do not read the other two skills.

## Step 2 — Run the triage

Follow the chosen skill exactly as written. In particular:

- Apply the MANDATORY RULE — Production Code Assumption.
- Read `source_file` directly. Include the surrounding context the skill calls for (typically 20–30 lines).
- Explore related files only when the skill instructs and only when they bear on the assessment.
- Make decisions per the skill's framework, citing concrete `file:line` evidence at every step.
- If `source_file` does not exist or the description is too sparse to verify, classify as UNCLEAR rather than guess.

## Step 3 — Emit structured output

Write a JSON file to `triage-output.json` at the workflow workspace root with **exactly** this shape:

```json
{
  "verdict": "TRUE_POSITIVE",
  "comment_markdown": "<full triage report formatted per the chosen skill's output template, in Jira-flavored markdown>"
}
```

Rules:

- `verdict` must be one of `TRUE_POSITIVE`, `FALSE_POSITIVE`, `UNCLEAR` — exact strings, no other values.
- `comment_markdown` must contain the full triage report following the skill's output template. Include `file:line` evidence for every claim. Use `**bold**` for headings and triple-backtick fences for code; Jira renders these.
- Do **not** include the verdict label or footer in `comment_markdown` — those are added automatically by the post-step.

After writing the JSON, call the `upload_asset` safe-output with `path: "triage-output.json"` so a downstream job can read it. Then call `noop` with a one-sentence summary.

## Constraints

- Do not modify any files in the checked-out repository. Your only file write is `triage-output.json`.
- Do not invent file paths or line numbers. If a path you were given does not exist, classify as UNCLEAR and explain in the comment.
- Do not access the network. The repository plus the parsed Jira fields are everything you need.
