# Leak Triage

[![GitHub](https://img.shields.io/badge/github-shreeramdas241%2Fleak--triage-181717?logo=github)](https://github.com/shreeramdas241/leak-triage)

**Repository threat intelligence for AppSec.** Leak Triage clones a list of Git URLs, runs [Gitleaks](https://github.com/gitleaks/gitleaks) for hardcoded secrets, scores **weighted heuristics** (payment, phishing UI, cloud, automation), and writes a **CSV + HTML** report with **redacted file:line evidence**.

Use it only on repositories you are authorized to assess (your org’s public leaks, bug-bounty in-scope assets, or explicitly approved third-party reviews).

Repo: **https://github.com/shreeramdas241/leak-triage**

## Why this exists

Public Git history is one of the fastest ways production credentials, merchant IDs, and cloned login flows leak. Leak Triage is a **batch triage** layer: it does not replace a full source review, but it scores volume so an AppSec engineer can spend time on `CRITICAL_THREAT` and `HIGH_THREAT` first.

## Install

You need **Python 3.10+** and **Git**. **Gitleaks** is optional but recommended for secret detection.

**Windows (PowerShell):**

```powershell
winget install --id Git.Git -e
winget install Gitleaks.Gitleaks
```

Close and reopen the terminal, then:

```powershell
git --version
python --version
gitleaks version
```

**macOS:**

```bash
brew install git gitleaks python
```

Clone and run (no `pip install` — stdlib only):

```powershell
git clone https://github.com/shreeramdas241/leak-triage.git
cd leak-triage
copy urls.example.txt urls.txt
notepad urls.txt
python leak_triage.py
```

macOS / Linux: `cp urls.example.txt urls.txt` then `python3 leak_triage.py`.

Put **one Git URL or local repo path per line** in `urls.txt`. Reports:

- `intelligence_audit.csv`
- `intelligence_audit.html`

If Gitleaks is missing, heuristics still run (`Scanner=MISSING`).

## What you get

| Column | Meaning |
| --- | --- |
| `Repo_URL` | Target clone URL |
| `Verdict` | `CRITICAL_THREAT` · `HIGH_THREAT` · `MEDIUM_THREAT` · `INFORMATIONAL` · `CLONE_FAILED` |
| `Score` | Weighted signal total (test paths are discounted) |
| `Risk_Category` | Highest-weight contributor |
| `Technical_Context` | Why the score landed there |
| `Asset_Exposure` | Tagged classes (AWS, API keys, merchant ID, cloud storage) |
| `Identity` | Latest commit author email; `[CORP]` if it matches `--domain` |
| `Scanner` | `gitleaks`, `gitleaks-history`, or `MISSING` |
| `Evidence` | Redacted `path:line [rule] snippet` hits |

Open `intelligence_audit.html` for counts and a ranked table. Secrets in reports are masked (`AKIA...Xyz9`), not dumped live.

## Scoring

Signals add weight. Hits that live only under `tests/`, `spec/`, `e2e/`, etc. are multiplied by `0.25` (see `rules.json`). Combos add extra weight:

| Signal / combo | Default weight |
| --- | --- |
| AWS credentials (Gitleaks) | 70 |
| Phishing UI markers | 45 |
| API keys / tokens | 40 |
| Payment / merchant markers | 35 |
| Cloud endpoints | 30 |
| Generic secrets | 30 |
| Browser automation | 25 |
| Gateway **and** automation | +50 |
| Cloud endpoint **and** secrets | +45 |

Verdict thresholds (configurable in `rules.json`):

- **CRITICAL** ≥ 80
- **HIGH** ≥ 50
- **MEDIUM** ≥ 25
- else **INFORMATIONAL**

A Selenium helper only in `tests/` will not look like a payment bot. The same helper next to `merchant_key` in `src/` will.

Edit `rules.json` to add packs without touching Python.

## CLI

```powershell
python leak_triage.py -i urls.txt -o intelligence_audit.csv --html intelligence_audit.html -w 5 -d example.com
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `-i` / `--input` | `urls.txt` | Target list |
| `-o` / `--output` | `intelligence_audit.csv` | CSV path |
| `--html` | `intelligence_audit.html` | HTML summary |
| `--no-html` | off | Skip HTML |
| `-w` / `--workers` | `5` | Parallel clones |
| `-d` / `--domain` | `example.com` | Corporate email suffix for `[CORP]` |
| `--rules` | `rules.json` | Weights and regex packs |
| `--depth` | `1` | Shallow clone depth |
| `--history` | off | Full clone + Gitleaks **git history** (secrets not in HEAD) |
| `--fail-on` | empty | Exit `2` if any row matches (e.g. `CRITICAL_THREAT`) |

```powershell
python leak_triage.py --history -w 2
python leak_triage.py --depth 50
python leak_triage.py --fail-on CRITICAL_THREAT
```

## How a scan works

1. **Clone** — `git clone --depth 1` by default (`GIT_TERMINAL_PROMPT=0`). `--history` drops `--depth`. `--depth N` keeps a shallow window.
2. **Author** from `git log -1 --format=%ae`.
3. **Gitleaks** — working-tree `--no-git` on depth 1; **git-aware** when `--history` or `--depth > 1`.
4. **Heuristics** from `rules.json` with file:line matches (not binary, not `node_modules`).
5. **Weighted score** + redacted evidence.
6. **Cleanup** — clone directories are deleted after each repo.

Temporary clones live as `intel_<nanoseconds>/` next to the script. Interrupted runs may leave leftovers; they are gitignored.

## Tests

```powershell
python -m unittest tests.test_scoring -v
```

Covers redaction, test-path discount detection, Gitleaks rule rollups, and verdict thresholds.

## Responsible use

- Authorized targets only. Cloning and secret-scanning repos you do not have permission to assess can violate law and policy.
- Findings can still hint at live credentials. Keep `urls.txt` and reports out of git (already gitignored). Rotate anything confirmed real.
- Do not use this to weaponize payment bots, phishing kits, or stolen cloud keys. The classifications exist so you can **take them down and remediate**.

## Project layout

```
leak-triage/
├── leak_triage.py         # scanner (CLI)
├── rules.json             # weights, thresholds, regex packs
├── urls.example.txt       # copy to urls.txt
├── tests/
│   └── test_scoring.py
├── LICENSE                # MIT
└── README.md
```

`urls.txt`, `intelligence_audit.csv`, and `intelligence_audit.html` are gitignored.

## License

MIT. See [LICENSE](LICENSE).
