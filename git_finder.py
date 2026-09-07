#!/usr/bin/env python3
"""Git_Finder — repository threat intelligence audit for AppSec reviews."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DEFAULT_INPUT = "urls.txt"
DEFAULT_OUTPUT = "intelligence_audit.csv"
DEFAULT_WORKERS = 5
DEFAULT_DOMAIN = "example.com"

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
}

TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".kt",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".m",
    ".mm",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".rs",
    ".scala",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".env",
    ".xml",
    ".html",
    ".htm",
    ".css",
    ".md",
    ".txt",
    ".csv",
    ".sql",
    ".tf",
    ".tfvars",
    ".gradle",
    ".properties",
    ".conf",
    ".cfg",
    ".plist",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clone listed Git repositories and classify leaked-secret / threat heuristics.",
    )
    parser.add_argument("-i", "--input", default=DEFAULT_INPUT, help="Newline-separated repository URLs")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="CSV report path")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help="Parallel clone/scan workers")
    parser.add_argument(
        "-d",
        "--domain",
        default=DEFAULT_DOMAIN,
        help="Corporate email domain used for identity tagging (e.g. example.com)",
    )
    return parser.parse_args()


class RepositoryAnalyzer:
    def __init__(self, target_url: str, corp_domain: str) -> None:
        self.target_url = target_url.strip()
        self.repo_dir = Path(f"intel_{time.time_ns()}")
        self.corp_email_re = re.compile(rf"@{re.escape(corp_domain)}$", re.IGNORECASE)
        self.env = os.environ.copy()
        self.env["GIT_TERMINAL_PROMPT"] = "0"
        self._file_cache: list[Path] | None = None

    def clone_repository(self) -> bool:
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", self.target_url, str(self.repo_dir)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=self.env,
                check=True,
            )
            return self.repo_dir.exists()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def get_commit_author(self) -> str:
        try:
            result = subprocess.run(
                ["git", "log", "-1", "--format=%ae"],
                cwd=self.repo_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=True,
            )
            email = result.stdout.strip().replace(",", "")
            if email and self.corp_email_re.search(email):
                return f"{email} [CORP]"
            return email or "UNKNOWN"
        except subprocess.CalledProcessError:
            return "UNKNOWN"

    def run_gitleaks(self) -> dict:
        report_file = Path(f"{self.repo_dir}_gitleaks.json")
        detected_types: set[str] = set()
        has_secrets = False
        try:
            completed = subprocess.run(
                [
                    "gitleaks",
                    "detect",
                    "--source",
                    ".",
                    "--no-git",
                    "--report-format",
                    "json",
                    "--report-path",
                    str(report_file.resolve()),
                ],
                cwd=self.repo_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if completed.returncode == 127 or shutil.which("gitleaks") is None:
                return {"has_secrets": False, "types": [], "scanner": "MISSING"}
            if report_file.exists() and report_file.stat().st_size > 0:
                try:
                    findings = json.loads(report_file.read_text(encoding="utf-8", errors="ignore"))
                except json.JSONDecodeError:
                    findings = []
                if findings:
                    has_secrets = True
                    for item in findings:
                        rule_id = str(item.get("RuleID", "generic-secret")).lower()
                        if "aws" in rule_id:
                            detected_types.add("AWS_Credentials")
                        elif any(token in rule_id for token in ("key", "api", "token")):
                            detected_types.add("API_Keys")
                        else:
                            detected_types.add("Generic_Secrets")
        except FileNotFoundError:
            return {"has_secrets": False, "types": [], "scanner": "MISSING"}
        finally:
            if report_file.exists():
                report_file.unlink(missing_ok=True)
        return {"has_secrets": has_secrets, "types": list(detected_types), "scanner": "gitleaks"}

    def _iter_text_files(self) -> list[Path]:
        if self._file_cache is not None:
            return self._file_cache
        files: list[Path] = []
        for path in self.repo_dir.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {".env", "Dockerfile", "Jenkinsfile"}:
                continue
            if path.stat().st_size > 2_000_000:
                continue
            files.append(path)
        self._file_cache = files
        return files

    def search_patterns(self, pattern: str) -> bool:
        compiled = re.compile(pattern, re.IGNORECASE)
        for path in self._iter_text_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if compiled.search(text):
                return True
        return False

    def analyze(self) -> dict:
        if not self.clone_repository():
            return {
                "Repo_URL": self.target_url,
                "Verdict": "CLONE_FAILED",
                "Risk_Category": "INACCESSIBLE",
                "Technical_Context": "N/A",
                "Asset_Exposure": "None",
                "Identity": "N/A",
            }

        try:
            email = self.get_commit_author()
            gitleaks_results = self.run_gitleaks()
            has_gitleaks_secrets = gitleaks_results["has_secrets"]
            gitleaks_types = gitleaks_results["types"]

            gateway = self.search_patterns(
                r"MID_|merchant_key|checksum|example_mid|staging_mid|payment_params"
            )
            phishing = self.search_patterns(
                r"login-container|verify-otp|otp-input|sign-in-button"
            )
            cloud = self.search_patterns(
                r"s3\.amazonaws|firebaseio\.com|mongodb\+srv|database_url"
            )
            is_bot = self.search_patterns(
                r"puppeteer|selenium|chromedriver|headless|request-payload"
            )

            if gateway and is_bot:
                verdict = "CRITICAL_THREAT"
                risk = "PAYMENT_AUTOMATION_BOT"
                tech = "Live Gateway + Automation"
            elif "AWS_Credentials" in gitleaks_types or (cloud and has_gitleaks_secrets):
                verdict = "CRITICAL_THREAT"
                risk = "CLOUD_INFRASTRUCTURE_EXPOSURE"
                tech = "Exposed AWS/Cloud Secret"
            elif phishing:
                verdict = "HIGH_THREAT"
                risk = "PHISHING_UI_CLONE"
                tech = "Login Mimicry"
            elif has_gitleaks_secrets or gateway:
                verdict = "MEDIUM_THREAT"
                risk = "HARDCODED_API_KEYS"
                tech = (
                    f"Secrets Found: {', '.join(gitleaks_types)}"
                    if gitleaks_types
                    else "Generic Tokens"
                )
            elif gitleaks_results.get("scanner") == "MISSING":
                verdict = "INFORMATIONAL"
                risk = "SCANNER_UNAVAILABLE"
                tech = "Gitleaks not installed; heuristic-only scan"
            else:
                verdict = "INFORMATIONAL"
                risk = "GENERAL_CODE_LEAK"
                tech = "Proprietary Logic"

            assets: list[str] = []
            if gateway:
                assets.append("Merchant_ID")
            if cloud:
                assets.append("Cloud_Storage")
            if gitleaks_types:
                assets.extend(gitleaks_types)
            asset_str = ";".join(sorted(set(assets))) if assets else "None"

            return {
                "Repo_URL": self.target_url,
                "Verdict": verdict,
                "Risk_Category": risk,
                "Technical_Context": tech,
                "Asset_Exposure": asset_str,
                "Identity": email,
            }
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        if self.repo_dir.exists():
            shutil.rmtree(self.repo_dir, ignore_errors=True)


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file '{input_path}' not found.")
        print("Copy urls.example.txt to urls.txt and add one repository URL per line.")
        sys.exit(1)

    urls = [line.strip() for line in input_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not urls:
        print(f"Error: '{input_path}' is empty.")
        sys.exit(1)

    print(f"[*] Starting Git_Finder audit on {len(urls)} repositories ({args.workers} workers)...")
    fieldnames = [
        "Repo_URL",
        "Verdict",
        "Risk_Category",
        "Technical_Context",
        "Asset_Exposure",
        "Identity",
    ]

    with open(args.output, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
            future_to_url = {
                executor.submit(RepositoryAnalyzer(url, args.domain).analyze): url for url in urls
            }
            for future in as_completed(future_to_url):
                result = future.result()
                writer.writerow(result)
                print(f"Completed: {result['Repo_URL']} | Verdict: {result['Verdict']}")

    print("------------------------------------------------")
    print(f"[*] Git_Finder complete. Report: {args.output}")


if __name__ == "__main__":
    main()
