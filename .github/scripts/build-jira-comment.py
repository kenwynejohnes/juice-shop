#!/usr/bin/env python3
"""
Render a SAST triage JSON object into a Jira wiki-markup comment body.

Usage:
    build-jira-comment.py <triage-output.json> <run-url> [--repo-base-url URL]

Reads the JSON file, dispatches on triager_type ("general" | "password" | "ssrf"),
and prints the rendered Jira wiki-markup comment body to stdout. Exits non-zero on
schema violations.

Stdlib only — no third-party dependencies.

Ported from codemie's Jinja template at
ai-for-sec-demo-stand/codemie-setup/scenarios/jira/workflow-jira.md (lines 130–243).
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any


# ---------- escaping ----------

_SAFE_CHAR_REPLACEMENTS = [
    ("\\", "\\\\"),
    ("{", "\\{"),
    ("}", "\\}"),
    ("[", "\\["),
    ("]", "\\]"),
    ("_", "\\_"),
    ("-", "\\-"),
    ("!", "\\!"),
]


def safe(text: Any) -> str:
    """
    Escape free-form prose for Jira wiki markup. Mirrors codemie's `safe()` macro:
    backslash-escape Jira special characters, defang URLs.

    URLs are defanged (https:// -> hxxps://) so prose mentions of URLs in agent
    output don't auto-link or interfere with Jira's link syntax. Use the
    `wiki_link()` helper below to produce real clickable links.
    """
    if text is None:
        return ""
    s = str(text)
    for needle, replacement in _SAFE_CHAR_REPLACEMENTS:
        s = s.replace(needle, replacement)
    s = s.replace("https://", "hxxps://").replace("http://", "hxxp://")
    s = s.replace("(/)", "(\\/)")
    return s


def wiki_link(label: str, url: str) -> str:
    """Produce a clickable Jira wiki link `[label|url]`. Label is NOT safe()-escaped
    here because Jira link labels handle their own context; the caller decides."""
    return f"[{label}|{url}]"


# ---------- language normalization ----------

_LANG_MAP = {
    "typescript": "javascript",
    "ts": "javascript",
    "tsx": "javascript",
    "jsx": "javascript",
    "yml": "yaml",
    "csharp": "c#",
}


def jira_code_lang(lang: str | None) -> str:
    if not lang:
        return "none"
    normalized = _LANG_MAP.get(lang.lower(), lang.lower())
    return normalized or "none"


# ---------- decision color ----------

_DECISION_COLORS = {
    "TRUE POSITIVE": "#d04437",
    "FALSE POSITIVE": "#14892c",
    "UNCLEAR": "#f6c342",
    "NEEDS REVIEW": "#f6c342",
}


def decision_color(decision: str) -> str:
    return _DECISION_COLORS.get(decision, "#707070")


# ---------- common header / footer ----------

def render_header(decision: str, category: str, vulnerability_class: str | None) -> str:
    color = decision_color(decision)
    cat_display = category if category and category != "N/A" else "Not Available"
    lines = [
        "{color:#707070}🤖 _AI-generated analysis — please verify responses._{color}",
        "",
        "{panel:title=📊 Analysis Summary|borderStyle=solid|borderColor=#ccc|titleBGColor=#e8ecf0|bgColor=#fff}",
        f"*Decision*: {{color:{color}}}{decision}{{color}}",
        f"*Category*: {cat_display}",
    ]
    if vulnerability_class:
        lines.append(f"*Vulnerability Class*: {safe(vulnerability_class)}")
    lines.append("{panel}")
    lines.append("")
    return "\n".join(lines)


def render_code_block(snippet: str, lang: str | None) -> str:
    return "\n".join([
        f"{{code:{jira_code_lang(lang)}}}",
        snippet.rstrip(),
        "{code}",
    ])


def render_footer(run_url: str, decision: str) -> str:
    return "\n".join([
        "",
        "----",
        f"_Posted by [SAST Triage workflow|{run_url}] — verdict: {decision}_",
    ])


# ---------- per-triager renderers ----------

def render_general(d: dict, run_url: str) -> str:
    parts = [render_header(d["triage_decision"], d.get("category", "N/A"), d.get("vulnerability_class"))]

    if d.get("summary"):
        parts.append(f"*Summary*: {safe(d['summary'])}")
        parts.append("")

    parts.append("h2. Vulnerable Code Snippet")
    if d.get("code_location"):
        parts.append(f"{{{{{d['code_location']}}}}}")
    parts.append(render_code_block(d.get("code_snippet", ""), d.get("code_snippet_language")))
    parts.append("")

    parts.append("h2. Code Summary")
    parts.append(safe(d.get("code_summary", "")))
    parts.append("")

    parts.append("h2. Review Scope")
    files = d.get("files_examined") or []
    if files:
        files_md = ", ".join(f"_{{{{{f}}}}}_" for f in files)
        parts.append(f"*Files Examined*: {files_md}")
    parts.append("")
    parts.append(f"*Search Performed*: {safe(d.get('search_description', ''))}")
    parts.append("")

    parts.append("h2. Analysis")
    parts.append(f"*Vulnerability in Code*: {d.get('vulnerability_in_code', 'UNCLEAR')} - {safe(d.get('vulnerability_explanation', ''))}")
    parts.append("")

    if d.get("vulnerability_in_code") == "TRUE":
        parts.append(f"*Impact*: {d.get('impact_assessment', 'UNCLEAR')} - {safe(d.get('impact_explanation', ''))}")
        parts.append("")

        if d.get("impact_assessment") not in (None, "FALSE", "N/A", ""):
            parts.append(f"*Exploitable*: {d.get('exploitable_assessment', 'UNCLEAR')} - {safe(d.get('exploitable_explanation', ''))}")
            parts.append("")

            if d.get("is_taint_flow_vuln"):
                parts.append(f"* External Input: {d.get('external_input', 'UNCLEAR')}")
                parts.append(f"* Trust Level: {d.get('trust_level', 'UNCLEAR')}")
                parts.append(f"* Taint Flow: {d.get('taint_flow', 'UNCLEAR')}")
                parts.append(f"* Sink Usage: {d.get('sink_usage', 'UNCLEAR')}")
            else:
                parts.append("* Note: Configuration/Design Issue — presence equals exploitability")
            parts.append("")

    parts.append("*Compensatory Controls Found*:")
    parts.append(safe(d.get("compensatory_controls", "N/A")))
    parts.append("")

    parts.append("*Key Facts*:")
    for fact in d.get("key_facts") or []:
        parts.append(f"* {safe(fact)}")
    parts.append("")

    if d.get("triage_decision") == "UNCLEAR":
        review = d.get("manual_review_points") or []
        if review:
            parts.append("h2. Points Requiring Manual Review")
            for pt in review:
                parts.append(f"* {safe(pt)}")
            parts.append("")

    additional = d.get("additional_observations") or []
    if additional:
        parts.append("h2. Additional Observations")
        for obs in additional:
            parts.append(f"* {safe(obs)}")
        parts.append("")

    parts.append(render_footer(run_url, d["triage_decision"]))
    return "\n".join(parts)


def render_password(d: dict, run_url: str) -> str:
    parts = [render_header(d["triage_decision"], d.get("category", "N/A"), d.get("vulnerability_class"))]

    if d.get("summary"):
        parts.append(f"*Summary*: {safe(d['summary'])}")
        parts.append("")

    parts.append("h2. Vulnerable Code Snippet")
    if d.get("code_location"):
        parts.append(f"{{{{{d['code_location']}}}}}")
    parts.append(render_code_block(d.get("code_snippet", ""), d.get("code_snippet_language")))
    parts.append("")

    parts.append("h2. Code Summary")
    parts.append(safe(d.get("code_summary", "")))
    parts.append("")

    parts.append("h2. Review Scope")
    files = d.get("files_examined") or []
    if files:
        files_md = ", ".join(f"_{{{{{f}}}}}_" for f in files)
        parts.append(f"*Files Examined*: {files_md}")
    parts.append("")
    parts.append(f"*Search Performed*: {safe(d.get('search_description', ''))}")
    parts.append("")

    parts.append("h2. Analysis")
    parts.append(f"*Analysis*: {safe(d.get('analysis_explanation', ''))}")
    parts.append("")

    parts.append("*Evidence*:")
    parts.append(f"* Pattern: {safe(d.get('pattern', ''))}")
    parts.append(f"* Context: {safe(d.get('context', ''))}")
    if d.get("flagged_value"):
        parts.append(f"* Flagged Value (redacted): {{{{{d['flagged_value']}}}}}")
    parts.append("")

    parts.append("*Risk Reduction Factors*:")
    factors = d.get("risk_reduction_factors") or []
    if factors:
        for f in factors:
            parts.append(f"* {safe(f)}")
    else:
        parts.append("N/A")
    parts.append("")

    parts.append("*Checks Performed*:")
    parts.append(f"* Test Environment: {'Yes' if d.get('is_test_environment') else 'No'}")
    enc_line = f"* Encrypted: {'Yes' if d.get('is_encrypted') else 'No'}"
    if d.get("is_encrypted") and d.get("encryption_details"):
        enc_line += f" ({safe(d['encryption_details'])})"
    parts.append(enc_line)
    fb_line = f"* Fallback Default: {'Yes' if d.get('is_fallback_default') else 'No'}"
    if d.get("is_fallback_default") and d.get("fallback_pattern"):
        fb_line += f" ({safe(d['fallback_pattern'])})"
    parts.append(fb_line)
    parts.append("")

    parts.append("*Key Facts*:")
    for fact in d.get("key_facts") or []:
        parts.append(f"* {safe(fact)}")
    parts.append("")

    additional = d.get("additional_observations") or []
    if additional:
        parts.append("h2. Additional Observations")
        for obs in additional:
            parts.append(f"* {safe(obs)}")
        parts.append("")

    parts.append(render_footer(run_url, d["triage_decision"]))
    return "\n".join(parts)


def render_ssrf(d: dict, run_url: str) -> str:
    parts = [render_header(d["triage_decision"], d.get("category", "N/A"), d.get("vulnerability_class"))]

    if d.get("summary"):
        parts.append(f"*Summary*: {safe(d['summary'])}")
        parts.append("")

    parts.append("h2. Vulnerable Code Snippet")
    if d.get("code_location"):
        parts.append(f"{{{{{d['code_location']}}}}}")
    parts.append(render_code_block(d.get("code_snippet", ""), d.get("code_snippet_language")))
    parts.append("")

    parts.append("h2. Code Summary")
    parts.append(safe(d.get("code_summary", "")))
    parts.append("")

    parts.append("h2. Review Scope")
    files = d.get("files_examined") or []
    if files:
        files_md = ", ".join(f"_{{{{{f}}}}}_" for f in files)
        parts.append(f"*Files Examined*: {files_md}")
    parts.append("")
    parts.append(f"*Search Performed*: {safe(d.get('search_description', ''))}")
    parts.append("")

    parts.append("h2. Analysis")
    parts.append(f"*SSRF Pattern Present?*: {d.get('ssrf_pattern_present', 'FALSE')} - {safe(d.get('ssrf_pattern_explanation', ''))}")
    parts.append("")
    parts.append(f"*Test Code?*: {'Yes' if d.get('is_test_code') else 'No'} - {safe(d.get('is_test_code_explanation', ''))}")
    parts.append("")

    if d.get("ssrf_pattern_present") == "TRUE":
        # Host control
        host_line = f"*Host/Full URL Control?*: {d.get('host_control', 'N/A')}"
        if d.get("host_control_explanation"):
            host_line += f" - {safe(d['host_control_explanation'])}"
        parts.append(host_line)
        parts.append("")
        if d.get("host_control") == "TRUE":
            mit_line = f"*Mitigations?*: {d.get('host_control_mitigations', 'N/A')}"
            if d.get("host_control_mitigations_explanation"):
                mit_line += f" - {safe(d['host_control_mitigations_explanation'])}"
            parts.append(mit_line)
            parts.append("")

        # Path control
        path_line = f"*Path Segment Control?*: {d.get('path_control', 'N/A')}"
        if d.get("path_control_explanation"):
            path_line += f" - {safe(d['path_control_explanation'])}"
        parts.append(path_line)
        parts.append("")
        if d.get("path_control") == "TRUE":
            mit_line = f"*Mitigations?*: {d.get('path_control_mitigations', 'N/A')}"
            if d.get("path_control_mitigations_explanation"):
                mit_line += f" - {safe(d['path_control_mitigations_explanation'])}"
            parts.append(mit_line)
            parts.append("")
            redir_line = f"*Redirect to Hostile Host?*: {d.get('redirect_to_hostile', 'N/A')}"
            if d.get("redirect_to_hostile_explanation"):
                redir_line += f" - {safe(d['redirect_to_hostile_explanation'])}"
            parts.append(redir_line)
            parts.append("")

        # Query control
        q_line = f"*Query Parameter Control?*: {d.get('query_control', 'N/A')}"
        if d.get("query_control_explanation"):
            q_line += f" - {safe(d['query_control_explanation'])}"
        parts.append(q_line)
        parts.append("")
        if d.get("query_control") == "TRUE":
            esc_line = f"*Host Escalation?*: {d.get('host_escalation', 'N/A')}"
            if d.get("host_escalation_explanation"):
                esc_line += f" - {safe(d['host_escalation_explanation'])}"
            parts.append(esc_line)
            parts.append("")

    parts.append(f"*Summary*: {safe(d.get('analysis_summary', ''))}")
    parts.append("")

    parts.append("*Key Facts*:")
    for fact in d.get("key_facts") or []:
        parts.append(f"* {safe(fact)}")
    parts.append("")

    additional = d.get("additional_observations") or []
    if additional:
        parts.append("h2. Additional Observations")
        for obs in additional:
            parts.append(f"* {safe(obs)}")
        parts.append("")

    parts.append(render_footer(run_url, d["triage_decision"]))
    return "\n".join(parts)


# ---------- dispatch ----------

_RENDERERS = {
    "general": render_general,
    "password": render_password,
    "ssrf": render_ssrf,
}


def render(data: dict, run_url: str) -> str:
    triager_type = data.get("triager_type")
    if triager_type not in _RENDERERS:
        raise ValueError(
            f"Unknown or missing triager_type: {triager_type!r}. "
            f"Expected one of: {sorted(_RENDERERS.keys())}"
        )
    decision = data.get("triage_decision")
    if decision not in ("TRUE POSITIVE", "FALSE POSITIVE", "UNCLEAR"):
        raise ValueError(f"Invalid triage_decision: {decision!r}")
    return _RENDERERS[triager_type](data, run_url)


# ---------- CLI ----------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_path", help="Path to triage-output.json")
    parser.add_argument("run_url", help="GitHub Actions run URL for the footer link")
    args = parser.parse_args(argv)

    with open(args.input_path, encoding="utf-8") as f:
        data = json.load(f)

    sys.stdout.write(render(data, args.run_url))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
