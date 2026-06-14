import json
import os
import subprocess
import sys

import requests

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
DEVIN_API_KEY = os.environ["DEVIN_API_KEY"]
PR_NUMBER = os.environ["PR_NUMBER"]
REPO = os.environ["REPO"]
BRANCH = os.environ["BRANCH"]
SCANNED_SHA = os.environ.get("SCANNED_SHA", "")

# Your 5 injected findings — filter to these for the demo
TARGET_FINDINGS = [
    {"file": "superset/key_value/utils.py", "test_id": "B324"},
    {"file": "superset/views/core.py", "test_id": "B608"},
    {"file": "superset/config.py", "test_id": "B105", "line_min": 1183, "line_max": 1188},
    {"file": "superset/views/core.py", "test_id": "B310"},
    {"file": "superset/utils/core.py", "test_id": "B602"},
]

SEVERITY_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}


def load_findings():
    with open("bandit_results.json") as f:
        data = json.load(f)
    results = []
    for r in data.get("results", []):
        rel_path = r["filename"].replace("./", "")
        for target in TARGET_FINDINGS:
            if target["file"] in rel_path and r["test_id"] == target["test_id"]:
                if "line_min" in target:
                    if target["line_min"] <= r["line_number"] <= target["line_max"]:
                        results.append(r)
                else:
                    results.append(r)
    return results


def get_git_blame(filepath, line_number):
    try:
        result = subprocess.run(
            ["git", "blame", "-L", f"{line_number},{line_number}", "--porcelain", filepath],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in result.stdout.splitlines():
            if line.startswith("author "):
                return line.replace("author ", "").strip()
    except Exception:
        pass
    return "Unknown"


def post_pr_review(findings):
    """Post a single structured review comment listing all findings."""
    sha_note = f"\n\n_Scanned commit: `{SCANNED_SHA[:7]}`_" if SCANNED_SHA else ""

    if not findings:
        body = f"## ✅ Security Scan Passed\n\nNo target security findings detected.{sha_note}"
        event = "APPROVE"
    else:
        rows = []
        for f in findings:
            filepath = f["filename"].replace("./", "")
            author = get_git_blame(filepath, f["line_number"])
            emoji = SEVERITY_EMOJI.get(f["issue_severity"], "⚪")
            rows.append(
                f"| {emoji} {f['issue_severity']} | `{f['test_id']}` | "
                f"`{filepath}:{f['line_number']}` | {f['issue_text'][:60]} | {author} |"
            )

        table = "\n".join(rows)
        body = f"""## 🔒 Security Scan — {len(findings)} Finding(s) Detected

| Severity | Rule | Location | Description | Introduced By |
|----------|------|----------|-------------|---------------|
{table}

**Devin is now remediating each finding automatically.** This PR will be updated with fixes shortly. Do not merge until the security scan passes on the latest commit.{sha_note}
"""
        event = "REQUEST_CHANGES"

    response = requests.post(
        f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}/reviews",
        headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json",
        },
        json={"body": body, "event": event},
        timeout=30,
    )
    response.raise_for_status()
    print(f"Posted PR review: {event}")


def trigger_devin_session(finding):
    filepath = finding["filename"].replace("./", "")
    code_snippet = finding.get("code", "").strip()

    prompt = f"""You are working on a pull request in a fork of Apache Superset.

## Your Task
Fix a security vulnerability that was detected by an automated scan on this PR.
Commit your fix directly to the branch `{BRANCH}` in the repository `https://github.com/{REPO}`.

## Vulnerability Details
- **Rule:** {finding["test_id"]}
- **Severity:** {finding["issue_severity"]}
- **File:** `{filepath}`
- **Line:** {finding["line_number"]}
- **Description:** {finding["issue_text"]}

## Vulnerable Code
```python
{code_snippet}
```

## Instructions
1. Navigate to `{filepath}` at line {finding["line_number"]}
2. Fix the vulnerability described above
3. Verify that running `bandit -r {filepath}` no longer reports {finding["test_id"]} on this code
4. Commit the fix to branch `{BRANCH}` with message: `fix: remediate {finding["test_id"]} in {filepath}`
5. Do not open a new PR — commit directly to the existing branch

## Acceptance Criteria
- [ ] {finding["test_id"]} no longer fires on the fixed code
- [ ] Function signatures and behavior are unchanged
- [ ] Fix is committed to branch `{BRANCH}`
"""

    response = requests.post(
        "https://api.devin.ai/v1/sessions",
        headers={
            "Authorization": f"Bearer {DEVIN_API_KEY}",
            "Content-Type": "application/json",
        },
        json={"prompt": prompt},
        timeout=30,
    )
    response.raise_for_status()

    session = response.json()
    print(f"Devin session started for {finding['test_id']}: {session.get('session_id')}")
    return session


def main():
    findings = load_findings()
    print(f"Found {len(findings)} target findings")

    post_pr_review(findings)

    for finding in findings:
        trigger_devin_session(finding)

    if findings:
        print("Security findings detected — re-run this workflow after Devin remediates.")
        sys.exit(1)

    print("Security scan passed.")


if __name__ == "__main__":
    main()
