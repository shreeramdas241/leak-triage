#!/usr/bin/env python3
"""Git_Finder — repository threat intelligence audit for AppSec reviews."""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT = "urls.txt"
DEFAULT_OUTPUT = "intelligence_audit.csv"
DEFAULT_HTML = "intelligence_audit.html"
DEFAULT_RULES = SCRIPT_DIR / "rules.json"
DEFAULT_WORKERS = 5
DEFAULT_DOMAIN = "example.com"
DEFAULT_DEPTH = 1
MAX_EVIDENCE = 12

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

VERDICT_RANK = {
    "CRITICAL_THREAT": 4,
    "HIGH_THREAT": 3,
    "MEDIUM_THREAT": 2,
    "INFORMATIONAL": 1,
    "CLONE_FAILED": 0,
}

CSV_FIELDS = [
    "Repo_URL",
    "Verdict",
    "Score",
    "Risk_Category",
    "Technical_Context",
    "Asset_Exposure",
    "Identity",
    "Scanner",
    "Evidence",
]


def redact_secret(value: str | None) -> str:
    """Mask a secret so reports are shareable without dumping live credentials."""
    if not value:
        return ""
    text = re.sub(r"\s+", "", str(value))
    if len(text) <= 8:
        return "*" * max(len(text), 4)
    return f"{text[:4]}...{text[-4:]}"


def is_test_path(rel_path: str, markers: list[str]) -> bool:
    parts = Path(rel_path.replace("\\", "/")).parts
    lowered = {p.lower() for p in parts}
    return any(marker in lowered for marker in markers)


def load_rules(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error: could not load rules from {path}: {exc}")
        sys.exit(1)


def classify_rule_id(rule_id: str) -> str:
    rid = rule_id.lower()
    if "aws" in rid:
        return "AWS_Credentials"
    if any(token in rid for token in ("key", "api", "token")):
        return "API_Keys"
    return "Generic_Secrets"


def verdict_from_score(score: float, thresholds: dict, scanner_missing: bool) -> str:
    if score >= thresholds.get("CRITICAL_THREAT", 80):
        return "CRITICAL_THREAT"
    if score >= thresholds.get("HIGH_THREAT", 50):
        return "HIGH_THREAT"
    if score >= thresholds.get("MEDIUM_THREAT", 25):
        return "MEDIUM_THREAT"
    if scanner_missing and score <= 0:
        return "INFORMATIONAL"
    return "INFORMATIONAL"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clone listed Git repositories and classify leaked-secret / threat heuristics.",
    )
    parser.add_argument("-i", "--input", default=DEFAULT_INPUT, help="Newline-separated repository URLs")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="CSV report path")
    parser.add_argument("--html", default=DEFAULT_HTML, help="HTML summary path")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML summary")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help="Parallel clone/scan workers")
    parser.add_argument(
        "-d",
        "--domain",
        default=DEFAULT_DOMAIN,
        help="Corporate email domain used for identity tagging (e.g. example.com)",
    )
    parser.add_argument("--rules", default=str(DEFAULT_RULES), help="Weighted heuristic rules JSON")
    parser.add_argument(
        "--depth",
        type=int,
        default=DEFAULT_DEPTH,
        help="Shallow clone depth (ignored when --history is set)",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Full git clone and Gitleaks history scan (finds secrets not in HEAD)",
    )
    parser.add_argument(
        "--fail-on",
        default="",
        help="Exit 2 if any row reaches this verdict (e.g. CRITICAL_THREAT)",
    )
    return parser.parse_args()


class RepositoryAnalyzer:
    def __init__(self, target_url: str, corp_domain: str, rules: dict, history: bool, depth: int) -> None:
        self.target_url = target_url.strip()
        self.repo_dir = Path(f"intel_{time.time_ns()}")
        self.corp_email_re = re.compile(rf"@{re.escape(corp_domain)}$", re.IGNORECASE)
        self.rules = rules
        self.history = history
        self.depth = max(1, depth)
        self.env = os.environ.copy()
        self.env["GIT_TERMINAL_PROMPT"] = "0"
        self._file_cache: list[Path] | None = None

    def clone_repository(self) -> bool:
        cmd = ["git", "clone"]
        if not self.history:
            cmd.extend(["--depth", str(self.depth)])
        cmd.extend([self.target_url, str(self.repo_dir)])
        try:
            subprocess.run(
                cmd,
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
        evidence: list[dict] = []
        if shutil.which("gitleaks") is None:
            return {"has_secrets": False, "types": [], "scanner": "MISSING", "evidence": []}
        cmd = ["gitleaks", "detect"]
        # HEAD-only clones have no useful history; scan the working tree.
        # --history or --depth > 1: let Gitleaks walk git commits.
        if not self.history and self.depth == 1:
            cmd.append("--no-git")
        cmd.extend(
            [
                "--source",
                ".",
                "--report-format",
                "json",
                "--report-path",
                str(report_file.resolve()),
            ]
        )
        try:
            subprocess.run(cmd, cwd=self.repo_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            findings: list = []
            if report_file.exists() and report_file.stat().st_size > 0:
                try:
                    loaded = json.loads(report_file.read_text(encoding="utf-8", errors="ignore"))
                    findings = loaded if isinstance(loaded, list) else []
                except json.JSONDecodeError:
                    findings = []
            for item in findings:
                rule_id = str(item.get("RuleID") or item.get("Rule") or "generic-secret")
                secret_type = classify_rule_id(rule_id)
                detected_types.add(secret_type)
                file_name = str(item.get("File") or item.get("FilePath") or "")
                line = item.get("StartLine") or item.get("Line") or ""
                secret = item.get("Secret") or item.get("Match") or ""
                evidence.append(
                    {
                        "kind": "secret",
                        "rule": secret_type,
                        "raw_rule": rule_id,
                        "path": file_name,
                        "line": line,
                        "snippet": redact_secret(str(secret)),
                    }
                )
        except FileNotFoundError:
            return {"has_secrets": False, "types": [], "scanner": "MISSING", "evidence": []}
        finally:
            if report_file.exists():
                report_file.unlink(missing_ok=True)
        return {
            "has_secrets": bool(detected_types),
            "types": list(detected_types),
            "scanner": "gitleaks-history" if self.history or self.depth > 1 else "gitleaks",
            "evidence": evidence,
        }

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
            try:
                if path.stat().st_size > 2_000_000:
                    continue
            except OSError:
                continue
            files.append(path)
        self._file_cache = files
        return files

    def search_heuristic(self, pattern: str, rule_id: str) -> list[dict]:
        compiled = re.compile(pattern, re.IGNORECASE)
        hits: list[dict] = []
        for path in self._iter_text_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                match = compiled.search(line)
                if not match:
                    continue
                rel = str(path.relative_to(self.repo_dir)).replace("\\", "/")
                hits.append(
                    {
                        "kind": "heuristic",
                        "rule": rule_id,
                        "path": rel,
                        "line": line_no,
                        "snippet": redact_secret(match.group(0)),
                    }
                )
                if len(hits) >= 8:
                    return hits
        return hits

    def score(self, gitleaks_results: dict, heuristic_hits: dict[str, list[dict]]) -> dict:
        thresholds = self.rules.get("thresholds", {})
        markers = [m.lower() for m in self.rules.get("test_path_markers", [])]
        test_mult = float(self.rules.get("test_path_multiplier", 0.25))
        secret_weights = self.rules.get("secret_weights", {})
        contributions: list[tuple[float, str, str]] = []
        score = 0.0
        fired: set[str] = set()

        for heuristic in self.rules.get("heuristics", []):
            hid = heuristic["id"]
            hits = heuristic_hits.get(hid) or []
            if not hits:
                continue
            fired.add(hid)
            weight = float(heuristic.get("weight", 0))
            if hits and all(is_test_path(h["path"], markers) for h in hits):
                weight *= test_mult
            score += weight
            contributions.append((weight, heuristic.get("risk", "GENERAL_CODE_LEAK"), heuristic.get("tech", hid)))

        types = gitleaks_results.get("types") or []
        secret_evidence = gitleaks_results.get("evidence") or []
        if types:
            fired.add("secrets")
            for secret_type in types:
                weight = float(secret_weights.get(secret_type, 30))
                type_hits = [e for e in secret_evidence if e.get("rule") == secret_type]
                if type_hits and all(is_test_path(str(e.get("path", "")), markers) for e in type_hits):
                    weight *= test_mult
                score += weight
                contributions.append((weight, "HARDCODED_API_KEYS", f"Secrets: {secret_type}"))

        for combo in self.rules.get("combos", []):
            required = set(combo.get("requires") or [])
            if required and required.issubset(fired):
                weight = float(combo.get("weight", 0))
                related_paths = []
                for hid in required:
                    if hid == "secrets":
                        related_paths.extend(str(e.get("path", "")) for e in secret_evidence)
                    else:
                        related_paths.extend(h["path"] for h in heuristic_hits.get(hid, []))
                if related_paths and all(is_test_path(p, markers) for p in related_paths if p):
                    weight *= test_mult
                score += weight
                contributions.append(
                    (weight, combo.get("risk", "GENERAL_CODE_LEAK"), combo.get("tech", combo.get("id", "combo")))
                )

        scanner_missing = gitleaks_results.get("scanner") == "MISSING"
        if not contributions and scanner_missing:
            risk = "SCANNER_UNAVAILABLE"
            tech = "Gitleaks not installed; heuristic-only scan"
            verdict = "INFORMATIONAL"
        elif not contributions:
            risk = "GENERAL_CODE_LEAK"
            tech = "No weighted signals"
            verdict = "INFORMATIONAL"
        else:
            contributions.sort(key=lambda item: item[0], reverse=True)
            _, risk, tech = contributions[0]
            verdict = verdict_from_score(score, thresholds, scanner_missing)
            if len(contributions) > 1:
                extra = "; ".join(item[2] for item in contributions[1:3])
                tech = f"{tech} | {extra}"

        return {
            "score": round(score, 1),
            "verdict": verdict,
            "risk": risk,
            "tech": tech,
        }

    def analyze(self) -> dict:
        blank = {
            "Repo_URL": self.target_url,
            "Verdict": "CLONE_FAILED",
            "Score": "0",
            "Risk_Category": "INACCESSIBLE",
            "Technical_Context": "N/A",
            "Asset_Exposure": "None",
            "Identity": "N/A",
            "Scanner": "N/A",
            "Evidence": "",
        }
        if not self.clone_repository():
            return blank

        try:
            email = self.get_commit_author()
            gitleaks_results = self.run_gitleaks()
            heuristic_hits: dict[str, list[dict]] = {}
            assets: list[str] = []
            evidence_rows: list[dict] = list(gitleaks_results.get("evidence") or [])

            for heuristic in self.rules.get("heuristics", []):
                hits = self.search_heuristic(heuristic["pattern"], heuristic["id"])
                heuristic_hits[heuristic["id"]] = hits
                if hits:
                    assets.append(heuristic.get("category", heuristic["id"]))
                    evidence_rows.extend(hits)

            if gitleaks_results.get("types"):
                assets.extend(gitleaks_results["types"])

            scored = self.score(gitleaks_results, heuristic_hits)
            evidence_txt = format_evidence(evidence_rows)
            return {
                "Repo_URL": self.target_url,
                "Verdict": scored["verdict"],
                "Score": str(scored["score"]),
                "Risk_Category": scored["risk"],
                "Technical_Context": scored["tech"],
                "Asset_Exposure": ";".join(sorted(set(assets))) if assets else "None",
                "Identity": email,
                "Scanner": gitleaks_results.get("scanner", "N/A"),
                "Evidence": evidence_txt,
            }
        finally:
            self.cleanup()

    def cleanup(self) -> None:
        if self.repo_dir.exists():
            shutil.rmtree(self.repo_dir, ignore_errors=True)


def format_evidence(rows: list[dict]) -> str:
    parts: list[str] = []
    for row in rows[:MAX_EVIDENCE]:
        path = row.get("path") or "?"
        line = row.get("line") or ""
        loc = f"{path}:{line}" if line else path
        parts.append(f"{loc} [{row.get('rule')}] {row.get('snippet', '')}".strip())
    extra = len(rows) - MAX_EVIDENCE
    if extra > 0:
        parts.append(f"+{extra} more")
    return " | ".join(parts)


def write_html_report(results: list[dict], path: Path) -> None:
    counts = Counter(row["Verdict"] for row in results)
    ordered = sorted(
        results,
        key=lambda row: (VERDICT_RANK.get(row["Verdict"], 0), float(row.get("Score") or 0)),
        reverse=True,
    )

    def card(label: str, key: str, css: str) -> str:
        return (
            f'<div class="card {css}"><div class="n">{counts.get(key, 0)}</div>'
            f"<div class=\"l\">{html.escape(label)}</div></div>"
        )

    rows_html = []
    for row in ordered:
        verdict = row["Verdict"]
        rows_html.append(
            "<tr>"
            f'<td class="v {verdict}">{html.escape(verdict)}</td>'
            f'<td>{html.escape(str(row.get("Score", "0")))}</td>'
            f'<td class="url">{html.escape(row["Repo_URL"])}</td>'
            f'<td>{html.escape(row.get("Risk_Category", ""))}</td>'
            f'<td>{html.escape(row.get("Technical_Context", ""))}</td>'
            f'<td>{html.escape(row.get("Asset_Exposure", ""))}</td>'
            f'<td>{html.escape(row.get("Identity", ""))}</td>'
            f'<td class="ev">{html.escape(row.get("Evidence", "") or "—")}</td>'
            "</tr>"
        )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Git_Finder intelligence audit</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; background: #0f1419; color: #e7ecf3; }}
    header {{ padding: 28px 32px 12px; }}
    h1 {{ margin: 0 0 6px; font-size: 1.6rem; }}
    .sub {{ color: #9aa8b8; margin-bottom: 20px; }}
    .cards {{ display: flex; gap: 12px; flex-wrap: wrap; padding: 0 32px 20px; }}
    .card {{ background: #1a222c; border-radius: 10px; padding: 14px 18px; min-width: 120px; }}
    .card .n {{ font-size: 1.6rem; font-weight: 700; }}
    .card .l {{ font-size: .78rem; color: #9aa8b8; }}
    .card.crit .n {{ color: #ff6b6b; }}
    .card.high .n {{ color: #ffb020; }}
    .card.med .n {{ color: #5cc8ff; }}
    .card.info .n {{ color: #8b9aab; }}
    .wrap {{ padding: 0 32px 40px; overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; font-size: .86rem; }}
    th, td {{ border-bottom: 1px solid #2a3542; padding: 8px 10px; text-align: left; vertical-align: top; }}
    th {{ color: #9aa8b8; font-weight: 600; position: sticky; top: 0; background: #0f1419; }}
    .url {{ word-break: break-all; max-width: 280px; }}
    .ev {{ word-break: break-word; max-width: 420px; color: #c5d0dc; font-family: ui-monospace, monospace; font-size: .78rem; }}
    .CRITICAL_THREAT {{ color: #ff6b6b; font-weight: 700; }}
    .HIGH_THREAT {{ color: #ffb020; font-weight: 700; }}
    .MEDIUM_THREAT {{ color: #5cc8ff; font-weight: 700; }}
    .INFORMATIONAL {{ color: #8b9aab; }}
    .CLONE_FAILED {{ color: #6b7c8d; }}
  </style>
</head>
<body>
  <header>
    <h1>Git_Finder</h1>
    <div class="sub">Weighted triage · redacted evidence · {len(results)} repositories</div>
  </header>
  <div class="cards">
    {card("Critical", "CRITICAL_THREAT", "crit")}
    {card("High", "HIGH_THREAT", "high")}
    {card("Medium", "MEDIUM_THREAT", "med")}
    {card("Informational", "INFORMATIONAL", "info")}
    {card("Clone failed", "CLONE_FAILED", "info")}
  </div>
  <div class="wrap">
    <table>
      <thead>
        <tr>
          <th>Verdict</th><th>Score</th><th>Repo</th><th>Risk</th>
          <th>Context</th><th>Assets</th><th>Identity</th><th>Evidence (redacted)</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows_html)}
      </tbody>
    </table>
  </div>
</body>
</html>
"""
    path.write_text(page, encoding="utf-8")


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

    rules = load_rules(Path(args.rules))
    mode = "full history" if args.history else f"depth {args.depth}"
    print(f"[*] Git_Finder v0.2 — {len(urls)} repos · {args.workers} workers · clone {mode}")

    results: list[dict] = []
    with open(args.output, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
            future_to_url = {
                executor.submit(
                    RepositoryAnalyzer(url, args.domain, rules, args.history, args.depth).analyze
                ): url
                for url in urls
            }
            for future in as_completed(future_to_url):
                result = future.result()
                writer.writerow(result)
                results.append(result)
                print(
                    f"Completed: {result['Repo_URL']} | {result['Verdict']} | score {result['Score']}"
                )

    if not args.no_html:
        html_path = Path(args.html)
        write_html_report(results, html_path)
        print(f"[*] HTML summary: {html_path}")

    print("------------------------------------------------")
    print(f"[*] Git_Finder complete. CSV: {args.output}")

    fail_on = (args.fail_on or "").strip().upper()
    if fail_on and any(row["Verdict"] == fail_on for row in results):
        print(f"[!] Fail-on matched: {fail_on}")
        sys.exit(2)


if __name__ == "__main__":
    main()
