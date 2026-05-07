---
description: Triage a single SAST finding using a vulnerability-type-matched skill from .github/skills/
on:
  workflow_dispatch:
    inputs:
      vulnerability_type:
        description: 'Vulnerability type (free text — e.g. "SSRF", "Hardcoded Password", "SQL Injection")'
        required: true
        type: string
      source_file:
        description: 'Path to the file containing the finding (relative to repo root)'
        required: true
        type: string
      source_line:
        description: 'Source line number or range (e.g. "74" or "74-98")'
        required: true
        type: string
      destination_file:
        description: 'Destination file path (optional, for data-flow findings)'
        required: false
        type: string
      destination_line:
        description: 'Destination line/range (optional)'
        required: false
        type: string
      vulnerability_description:
        description: 'Description from the SAST tool (optional)'
        required: false
        type: string
permissions:
  contents: read
engine: copilot
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
safe-outputs:
  upload-asset:
    allowed-exts: [".md"]
    max-size: 1024
timeout-minutes: 15
strict: true
---

# SAST Finding Triage

You are triaging a single SAST (Static Application Security Testing) finding for this repository.

## Finding details

- **vulnerability_type**: ${{ github.event.inputs.vulnerability_type }}
- **source_file**: ${{ github.event.inputs.source_file }}
- **source_line**: ${{ github.event.inputs.source_line }}
- **destination_file**: ${{ github.event.inputs.destination_file }}
- **destination_line**: ${{ github.event.inputs.destination_line }}
- **vulnerability_description**: ${{ github.event.inputs.vulnerability_description }}

## Step 1 — Pick the right skill

Match `vulnerability_type` (case-insensitive) against these patterns and read **only** the matching skill:

- Matches `ssrf` or `server.?side.?request.?forgery` → read `.github/skills/sast-triage-ssrf/SKILL.md`
- Otherwise matches any of `hardcoded`, `password`, `secret`, `credential`, `api.?key`, `token` → read `.github/skills/sast-triage-hardcoded-secrets/SKILL.md`
- Otherwise → read `.github/skills/sast-triage-general/SKILL.md`

Then read the `references/output-template.md` file under that same skill directory.

Do not read the other two skills. Do not read SKILL.md files you did not select.

## Step 2 — Run the triage

Follow the chosen skill exactly as written. In particular:

- Apply the MANDATORY RULE — Production Code Assumption.
- Read `source_file` directly using its path. Read `destination_file` the same way if provided. Include the surrounding context the skill calls for (typically 20–30 lines).
- Explore related files (route registrations, validators, helpers, configs) only as the skill instructs and only when they bear on the assessment.
- Make decisions per the skill's framework, citing concrete `file:line` evidence at every step.

## Step 3 — Emit the report

Produce the triage report in the exact format specified by the chosen skill's `references/output-template.md`. Follow the template's stage-gating, category rules, and formatting rules without deviation.

Save the final report to `triage-report.md` at the workflow workspace root, then call the `upload_asset` tool with `path: "triage-report.md"` to publish it. Do not use `noop` for the final output.

## Constraints

- Do not modify any files in the repository. Your only file write is `triage-report.md`.
- Do not invent file paths or line numbers. If a path you were given does not exist, say so in the report and classify as UNCLEAR.
- Do not access the network. Everything you need is in the repository.
