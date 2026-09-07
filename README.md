# Git_Finder

**Repository threat intelligence for AppSec.** Git_Finder clones a list of Git URLs, runs [Gitleaks](https://github.com/gitleaks/gitleaks) for hardcoded secrets, scores **weighted heuristics** (payment, phishing UI, cloud, automation), and writes a **CSV + HTML** report with **redacted file:line evidence**.

Use it only on repositories you are authorized to assess (your org’s public leaks, bug-bounty in-scope assets, or explicitly approved third-party reviews).

## Why this exists

Public Git history is one of the fastest ways production credentials, merchant IDs, and cloned login flows leak. Git_Finder is a **batch triage** layer: it does not replace a full source review, but it scores volume so an AppSec engineer can spend time on `CRITICAL_THREAT` and `HIGH_THREAT` first.

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

Open `intelligence_audit.html` for counts and a ranked table. Secrets in reports are masked (`AKIA…Xyz9`), not dumped live.

## Scoring (not a brittle if/else)

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

## Requirements

- Python 3.10+
- [Git](https://git-scm.com/)
- [Gitleaks](https://github.com/gitleaks/gitleaks) on `PATH` (optional but recommended)

No Python packages are required. The scanner is stdlib-only.

```powershell
winget install Gitleaks.Gitleaks
```

```bash
brew install gitleaks
```

If Gitleaks is missing, heuristics still run (`Scanner=MISSING`).

## Quick start

```bash
git clone https://github.com/shreeramdas241/Git_Finder.git
cd Git_Finder
copy urls.example.txt urls.txt   # Windows
# cp urls.example.txt urls.txt  # macOS / Linux
```

Edit `urls.txt` — one HTTPS, SSH, or local Git path per line. Then:

```bash
python git_finder.py
```

Reports: `intelligence_audit.csv` and `intelligence_audit.html`

### CLI

```bash
python git_finder.py -i urls.txt -o intelligence_audit.csv --html intelligence_audit.html -w 5 -d example.com
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
| `--history` | off | **Full clone + Gitleaks git history** (secrets not in HEAD) |
| `--fail-on` | empty | Exit `2` if any row matches (e.g. `CRITICAL_THREAT`) |

History scan (slower, more complete):

```bash
python git_finder.py --history -w 2
```

Partial history without a full clone:

```bash
python git_finder.py --depth 50
```

CI-style fail:

```bash
python git_finder.py --fail-on CRITICAL_THREAT
```

## How a scan works

1. **Clone** — `git clone --depth 1` by default (`GIT_TERMINAL_PROMPT=0`). `--history` drops `--depth`. `--depth N` keeps a shallow window.
2. **Author** from `git log -1 --format=%ae`.
3. **Gitleaks** — working-tree `--no-git` on depth 1; **git-aware** when `--history` or `--depth > 1`.
4. **Heuristics** from `rules.json` with file:line matches (not binary, not `node_modules`).
5. **Weighted score** + redacted evidence.
6. **Cleanup** — clone directories are deleted after each repo.

Temporary clones live as `intel_<nanoseconds>/` next to the script. Interrupted runs may leave leftovers; they are gitignored.

## Responsible use

- Authorized targets only. Cloning and secret-scanning repos you do not have permission to assess can violate law and policy.
- Findings can still hint at live credentials. Keep `urls.txt` and reports out of git (gitignored). Rotate anything confirmed real.
- Do not use this to weaponize payment bots, phishing kits, or stolen cloud keys. The classifications exist so you can **take them down and remediate**.

## Project layout

```
Git_Finder/
├── git_finder.py       # scanner
├── rules.json          # weights, thresholds, regex packs
├── urls.example.txt
├── LICENSE
└── README.md
```

## License

MIT. See [LICENSE](LICENSE).
