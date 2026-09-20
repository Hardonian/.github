#!/usr/bin/env python3
"""Agent Governance CI check — scans PR diffs for policy violations.

Runs inside GitHub Actions. Reads the diff from git, scans added/changed lines
for secrets, dangerous commands, protected path modifications, and classifies
overall risk. Outputs a Markdown report and sets exit code.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Bootstrap: ensure gateway package is importable
# ---------------------------------------------------------------------------
_GATEWAY_DIR = Path(__file__).resolve().parent.parent / "gateway"
if str(_GATEWAY_DIR.parent) not in sys.path:
    sys.path.insert(0, str(_GATEWAY_DIR.parent))

from gateway.secret_detector import SecretDetector, SecretMatch
from gateway.classifier import CommandClassifier, RiskLevel
from gateway.path_guard import PathGuard
from gateway import load_default_engine
from gateway.policy_engine import EnforcementDecision


# ---------------------------------------------------------------------------
# Diff parsing
# ---------------------------------------------------------------------------

@dataclass
class DiffHunk:
    """A single added/modified line from a unified diff."""
    file: str
    line_number: int
    content: str


def get_diff(base_ref: str, head_ref: str) -> list[DiffHunk]:
    """Get added/changed lines between two refs using git diff."""
    cmd = [
        "git", "diff", f"{base_ref}...{head_ref}",
        "--unified=0",        # zero context lines
        "--diff-filter=ACMR", # added, copied, modified, renamed
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"::warning::git diff failed: {result.stderr}", file=sys.stderr)
        return []

    return _parse_diff(result.stdout)


def _parse_diff(diff_text: str) -> list[DiffHunk]:
    """Parse unified diff output into added-line hunks."""
    hunks: list[DiffHunk] = []
    current_file = ""
    current_line = 0

    for line in diff_text.splitlines():
        # Track file names
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if line.startswith("--- "):
            continue

        # Hunk header: @@ -a,b +c,d @@
        hunk_match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if hunk_match:
            current_line = int(hunk_match.group(1))
            continue

        # Added lines
        if line.startswith("+") and not line.startswith("+++"):
            hunks.append(DiffHunk(
                file=current_file,
                line_number=current_line,
                content=line[1:],  # strip leading +
            ))
            current_line += 1
        elif line.startswith("-"):
            # Removed lines don't increment the new-file line counter
            pass
        else:
            # Context line
            current_line += 1

    return hunks


# ---------------------------------------------------------------------------
# Check results
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Accumulates all findings from a governance scan."""
    secrets: list[dict[str, Any]] = field(default_factory=list)
    dangerous_commands: list[dict[str, Any]] = field(default_factory=list)
    protected_paths: list[dict[str, Any]] = field(default_factory=list)
    risk_classifications: list[dict[str, Any]] = field(default_factory=list)
    policy_blocks: list[dict[str, Any]] = field(default_factory=list)
    policy_warnings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total_issues(self) -> int:
        return (
            len(self.secrets)
            + len(self.dangerous_commands)
            + len(self.protected_paths)
            + len(self.policy_blocks)
        )

    @property
    def has_critical(self) -> bool:
        return bool(self.secrets) or bool(self.protected_paths) or any(
            b.get("severity") == "CRITICAL" for b in self.policy_blocks
        )

    @property
    def max_risk(self) -> int:
        if not self.risk_classifications:
            return 0
        return max(r.get("risk_value", 0) for r in self.risk_classifications)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

# Regex patterns that look like embedded shell commands in scripts
_SHELL_CMD_PATTERN = re.compile(
    r"(?:^|\s|;|&&|\|\|)"
    r"(rm\s+-rf|curl\s+.*\|\s*(?:ba)?sh|wget\s+.*\|\s*(?:ba)?sh|"
    r"dd\s+.*of=/dev/|mkfs\.|:()\s*\{|shutdown|reboot|"
    r"chmod\s+777|chmod\s+\+s|eval\s*\(|exec\s*\()",
    re.IGNORECASE,
)

# Protected paths that should never be modified via PR
_PROTECTED_PATHS = [
    ".github/workflows",
    ".github/actions",
    "deploy/",
    "infrastructure/",
    "terraform/",
    "ansible/",
    "k8s/",
    "kubernetes/",
    "helm/",
    ".env.production",
    ".env.staging",
]


def scan_hunks(hunks: list[DiffHunk]) -> CheckResult:
    """Run all governance checks on diff hunks."""
    result = CheckResult()
    detector = SecretDetector()
    classifier = CommandClassifier()
    engine = load_default_engine()

    seen_secret_spans: set[tuple[str, int]] = set()
    seen_commands: set[str] = set()

    for hunk in hunks:
        # 1. Secret detection
        matches = detector.scan(hunk.content)
        for m in matches:
            key = (hunk.file, m.start)
            if key not in seen_secret_spans:
                seen_secret_spans.add(key)
                result.secrets.append({
                    "file": hunk.file,
                    "line": hunk.line_number,
                    "kind": m.kind,
                    "redacted": m.redacted,
                })

        # 2. Dangerous command detection in script content
        cmd_match = _SHELL_CMD_PATTERN.search(hunk.content)
        if cmd_match:
            cmd_text = cmd_match.group(0).strip()
            risk = classifier.classify(cmd_text)
            if risk.value >= RiskLevel.SYSTEM_MUTATION.value:
                cmd_key = f"{hunk.file}:{hunk.line_number}:{cmd_text}"
                if cmd_key not in seen_commands:
                    seen_commands.add(cmd_key)
                    result.dangerous_commands.append({
                        "file": hunk.file,
                        "line": hunk.line_number,
                        "command": cmd_text,
                        "risk_level": risk.name,
                    })

        # 3. Classify any shell-like commands found in the line
        # Look for patterns like: run: <command>, $(<command>), `<command>`
        embedded_cmds = re.findall(
            r'(?:run:\s*|exec:\s*|\$\(|`)([^`\n]{3,80})',
            hunk.content,
        )
        for cmd in embedded_cmds:
            cmd = cmd.strip().rstrip('`')
            if not cmd:
                continue
            risk = classifier.classify(cmd)
            result.risk_classifications.append({
                "file": hunk.file,
                "line": hunk.line_number,
                "command": cmd,
                "risk_level": risk.name,
                "risk_value": risk.value,
            })

            # Also run full policy engine evaluation
            decision: EnforcementDecision = engine.evaluate(
                command=cmd,
                paths=[hunk.file],
            )
            if not decision.allowed:
                result.policy_blocks.append({
                    "file": hunk.file,
                    "line": hunk.line_number,
                    "command": cmd,
                    "law_id": decision.law_id,
                    "reason": decision.reason,
                    "severity": decision.severity.value if decision.severity else "UNKNOWN",
                })
            elif decision.warnings:
                for w in decision.warnings:
                    result.policy_warnings.append({
                        "file": hunk.file,
                        "line": hunk.line_number,
                        "command": cmd,
                        "warning": w,
                    })

    # 4. Protected path detection (based on files changed, not content)
    changed_files = {h.file for h in hunks}
    for fpath in sorted(changed_files):
        for protected in _PROTECTED_PATHS:
            if fpath.startswith(protected) or fpath == protected.rstrip("/"):
                result.protected_paths.append({
                    "file": fpath,
                    "protected_pattern": protected,
                })
                break

    # 5. Assign overall risk for any commands not yet classified
    if not result.risk_classifications and hunks:
        # Classify the overall change set by its max risk
        for hunk in hunks:
            risk = classifier.classify(hunk.content.strip())
            if risk.value > RiskLevel.READ_ONLY.value:
                result.risk_classifications.append({
                    "file": hunk.file,
                    "line": hunk.line_number,
                    "command": hunk.content.strip()[:80],
                    "risk_level": risk.name,
                    "risk_value": risk.value,
                })

    return result


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(result: CheckResult, pr_number: int, repo: str) -> str:
    """Generate a Markdown governance report for a PR comment."""
    lines: list[str] = []

    # Header with status icon
    if result.has_critical:
        icon = "🔴"
        status = "CRITICAL ISSUES FOUND"
    elif result.total_issues > 0:
        icon = "🟡"
        status = "ISSUES FOUND"
    else:
        icon = "🟢"
        status = "ALL CHECKS PASSED"

    lines.append(f"## {icon} Agent Governance Check — {status}")
    lines.append("")

    # Summary table
    lines.append("| Check | Count |")
    lines.append("|-------|-------|")
    lines.append(f"| 🔑 Secrets detected | {len(result.secrets)} |")
    lines.append(f"| ⚠️ Dangerous commands | {len(result.dangerous_commands)} |")
    lines.append(f"| 🛡️ Protected path modifications | {len(result.protected_paths)} |")
    lines.append(f"| 🚫 Policy blocks | {len(result.policy_blocks)} |")
    lines.append(f"| ⚡ Policy warnings | {len(result.policy_warnings)} |")
    if result.risk_classifications:
        lines.append(f"| 📊 Max risk level | {RiskLevel(result.max_risk).name} |")
    lines.append("")

    # Detailed findings
    if result.secrets:
        lines.append("### 🔑 Secrets Detected")
        lines.append("")
        lines.append("Potential credentials found in the diff. **These must be removed before merging.**")
        lines.append("")
        lines.append("| File | Line | Type | Redacted |")
        lines.append("|------|------|------|----------|")
        for s in result.secrets:
            lines.append(f"| `{s['file']}` | {s['line']} | {s['kind']} | `{s['redacted']}` |")
        lines.append("")

    if result.protected_paths:
        lines.append("### 🛡️ Protected Path Modifications")
        lines.append("")
        lines.append("Changes to protected directories require explicit review.")
        lines.append("")
        lines.append("| File | Protected Pattern |")
        lines.append("|------|-------------------|")
        for p in result.protected_paths:
            lines.append(f"| `{p['file']}` | `{p['protected_pattern']}` |")
        lines.append("")

    if result.dangerous_commands:
        lines.append("### ⚠️ Dangerous Commands")
        lines.append("")
        lines.append("High-risk commands detected in added lines.")
        lines.append("")
        lines.append("| File | Line | Command | Risk |")
        lines.append("|------|------|---------|------|")
        for d in result.dangerous_commands:
            lines.append(f"| `{d['file']}` | {d['line']} | `{d['command']}` | {d['risk_level']} |")
        lines.append("")

    if result.policy_blocks:
        lines.append("### 🚫 Policy Blocks")
        lines.append("")
        lines.append("These changes violate governance policies and **must be fixed**.")
        lines.append("")
        lines.append("| File | Line | Command | Law | Severity | Reason |")
        lines.append("|------|------|---------|-----|----------|--------|")
        for b in result.policy_blocks:
            lines.append(
                f"| `{b['file']}` | {b['line']} | `{b['command']}` "
                f"| {b['law_id']} | {b['severity']} | {b['reason']} |"
            )
        lines.append("")

    if result.policy_warnings:
        lines.append("### ⚡ Policy Warnings")
        lines.append("")
        lines.append("These are advisory — no action required but review recommended.")
        lines.append("")
        for w in result.policy_warnings:
            lines.append(f"- `{w['file']}:{w['line']}` — {w['warning']}")
        lines.append("")

    if result.total_issues == 0:
        lines.append("No governance issues detected in this PR. ✅")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(
        "<sub>Powered by [Agent Governance Gateway](https://github.com/Hardonian/agent-governance) "
        f"• {len(result.risk_classifications)} commands classified</sub>"
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    base_ref = os.environ.get("GITHUB_BASE_REF", "origin/main")
    head_ref = os.environ.get("GITHUB_HEAD_REF", "HEAD")
    pr_number = int(os.environ.get("PR_NUMBER", "0"))
    repo = os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")
    output_file = os.environ.get("OUTPUT_FILE", "governance-report.md")
    fail_on_critical = os.environ.get("FAIL_ON_CRITICAL", "true").lower() == "true"
    fail_on_issues = os.environ.get("FAIL_ON_ISSUES", "false").lower() == "true"

    # For local testing: if no git diff possible, scan staged changes
    try:
        subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True, check=True,
        )
    except subprocess.CalledProcessError:
        print("::error::Not inside a git repository", file=sys.stderr)
        return 1

    # Get diff hunks
    print(f"Scanning diff: {base_ref}...{head_ref}", file=sys.stderr)
    hunks = get_diff(base_ref, head_ref)

    if not hunks:
        print("No added/modified lines found in diff.", file=sys.stderr)
        # Still generate a clean report
        result = CheckResult()
    else:
        print(f"Found {len(hunks)} added lines across "
              f"{len({h.file for h in hunks})} files.", file=sys.stderr)
        result = scan_hunks(hunks)

    # Generate report
    report = generate_report(result, pr_number, repo)

    # Write report to file for the workflow to use
    report_path = Path(output_file)
    report_path.write_text(report)
    print(f"Report written to {report_path}", file=sys.stderr)

    # Also write structured JSON for programmatic consumption
    json_path = report_path.with_suffix(".json")
    json_path.write_text(json.dumps({
        "secrets": result.secrets,
        "dangerous_commands": result.dangerous_commands,
        "protected_paths": result.protected_paths,
        "policy_blocks": result.policy_blocks,
        "policy_warnings": result.policy_warnings,
        "risk_classifications": result.risk_classifications,
        "total_issues": result.total_issues,
        "has_critical": result.has_critical,
        "max_risk": result.max_risk,
    }, indent=2))

    # Set GitHub Actions outputs
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a") as f:
            f.write(f"has_issues={str(result.total_issues > 0).lower()}\n")
            f.write(f"has_critical={str(result.has_critical).lower()}\n")
            f.write(f"total_issues={result.total_issues}\n")
            f.write(f"max_risk={result.max_risk}\n")

    # Exit code
    if fail_on_critical and result.has_critical:
        print("::error::CRITICAL governance issues found — failing check.", file=sys.stderr)
        return 1
    if fail_on_issues and result.total_issues > 0:
        print("::error::Governance issues found — failing check.", file=sys.stderr)
        return 1

    if result.total_issues > 0:
        print(f"::warning::{result.total_issues} governance issue(s) found (non-blocking).",
              file=sys.stderr)
    else:
        print("All governance checks passed.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
