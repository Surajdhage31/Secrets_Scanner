#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
from pathlib import Path

RULES = {
    "AWS_ACCESS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    "GITHUB_TOKEN": re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
    "SLACK_WEBHOOK": re.compile(
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"
    ),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----"),
}

IGNORE_DIRS = {".git", "node_modules", "venv", "__pycache__", ".idea", ".vscode"}
IGNORE_EXTS = {".png", ".jpg", ".jpeg", ".zip", ".tar", ".gz", ".pyc", ".lock"}

def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 4)

def is_text_file(filepath: Path) -> bool:
    if filepath.suffix.lower() in IGNORE_EXTS:
        return False
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" not in chunk
    except OSError:
        return False

def scan_file(filepath: Path) -> list:
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                for rule_name, pattern in RULES.items():
                    matches = pattern.findall(line)
                    for match in matches:
                        findings.append({
                            "rule": rule_name,
                            "file": str(filepath),
                            "line": line_no,
                            "match": mask_secret(match),
                            "confidence": "high"
                        })
    except Exception as e:
        sys.stderr.write(f"Error reading {filepath}: {e}\n")
    return findings

def scan_directory(target_path: Path) -> list:
    all_findings = []
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for file in files:
            full_path = Path(root) / file
            if is_text_file(full_path):
                all_findings.extend(scan_file(full_path))
    return all_findings

def main():
    parser = argparse.ArgumentParser(description="Deterministic Secret Scanner")
    parser.add_argument("path", nargs="?", default=".", help="Directory or file path to scan (defaults to current directory)")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        sys.stderr.write(f"Path does not exist: {target}\n")
        sys.exit(2)

    findings = scan_directory(target) if target.is_dir() else scan_file(target)

    if args.format == "json":
        payload = {
            "target": str(target),
            "total_findings": len(findings),
            "findings": findings
        }
        print(json.dumps(payload, indent=2))
    else:
        if not findings:
            print(f" Scan Clean: No secrets found in {target}")
        else:
            print(f" Vulnerabilities Found: {len(findings)} secret(s) detected\n")
            print(f"{'Type':<18} {'File':<40} {'Line':<6} {'Snippet'}")
            print("-" * 85)
            for item in findings:
                print(f"{item['rule']:<18} {item['file']:<40} {item['line']:<6} {item['match']}")

    sys.exit(1 if len(findings) > 0 else 0)

if __name__ == "__main__":
    main()