# Shai-Hulud Worm Audit — Project Plan

> Single-repo CLI auditor (Python 3) that scans a project directory for present
> or historical traces of the **Shai-Hulud** npm/PyPI supply-chain worm
> (waves: Sept 2025 v1, Nov 2025 v2 "Second Coming", Dec 2025 v3, May 2026
> Mini Shai-Hulud / cross-ecosystem). Vendored IOC lists with `--update`
> auto-refresh.

---

## 1. Threat Background (verifiable references)

### 1.1 Wave 1 — Shai-Hulud v1 (September 2025)

On **2025-09-15** a self-replicating worm published malicious versions of
`@ctrl/tinycolor` (≈2M weekly downloads) and ≈180+ further npm packages over
the next days, eventually exceeding **500 packages**. Each compromised release
shipped a `postinstall` hook executing a ~3 MB `bundle.js` that:

1. Ran a vendored, repurposed copy of **TruffleHog** to scrape secrets
   (`.npmrc`, `.env`, AWS/GCP/Azure creds, GitHub PATs, SSH keys).
2. Uploaded the loot, double-Base64-encoded, to a new **public** GitHub
   repository named `Shai-Hulud` (file `data.json`) on the victim's account.
3. Forked every private repo as a `*-migration` public repo with description
   `Shai-Hulud Migration`.
4. Pushed `.github/workflows/shai-hulud-workflow.yml` (on a branch
   `shai-hulud`) that re-exfiltrates secrets via Actions, with an outbound
   call to `hxxps://webhook[.]site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`.
5. Used the harvested npm token to re-publish further packages maintained by
   the victim — self-propagation.

**Primary sources:**
- [CISA Alert — Widespread Supply Chain Compromise Impacting npm Ecosystem (2025-09-23)](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Unit 42 / Palo Alto — "Shai-Hulud" Worm Compromises npm Ecosystem](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Sysdig — Shai-Hulud: novel self-replicating worm infecting hundreds of NPM packages](https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages)
- [Wiz — Shai-Hulud npm Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [ReversingLabs — Shai-Hulud npm supply chain attack: what you need to know](https://www.reversinglabs.com/blog/shai-hulud-worm-npm)
- [Phoenix Security — @ctrl/tinycolor and 526+ Packages, including CrowdStrike](https://phoenix.security/npm-shai-hulud-tinycolor-compromise/)
- [Socket — Ongoing Supply Chain Attack Targets CrowdStrike npm Packages](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- [JFrog — Shai-Hulud npm supply chain attack: new compromised packages detected](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)
- [Veracode — NPM Account Compromise — Tracking the Shai-Hulud Worm](https://www.veracode.com/blog/npm-account-compromise-the-shai-hulud-worm/)
- [Kaspersky — Responding to npm compromise by Shai-Hulud](https://www.kaspersky.com/blog/tinycolor-shai-hulud-supply-chain-attack/54315/)
- [Elastic — Navigating the Shai-Hulud worm](https://www.elastic.co/blog/shai-hulud-worm-npm-supply-chain-compromise)
- [Zscaler ThreatLabz — Mitigating Risks from the Shai-Hulud NPM Worm](https://www.zscaler.com/blogs/security-research/mitigating-risks-shai-hulud-npm-worm)
- [Trend Micro — What We Know About the NPM Supply Chain Attack](https://www.trendmicro.com/en_us/research/25/i/npm-supply-chain-attack.html)
- [Truesec — 500+ npm packages compromised](https://www.truesec.com/hub/blog/500-npm-packages-compromised-in-ongoing-supply-chain-attack-shai-hulud)
- [BleepingComputer — Self-propagating supply chain attack hits 187 npm packages](https://www.bleepingcomputer.com/news/security/self-propagating-supply-chain-attack-hits-187-npm-packages/)

### 1.2 Wave 2 — Shai-Hulud 2.0 / "Sha1-Hulud: The Second Coming" (November 2025)

Re-emerged **2025-11-21 → 11-24** and is materially more aggressive:

- **~796 unique packages / 1,092 unique versions** confirmed compromised
  (Datadog consolidated list, see §3).
- Notable namespaces affected: **Zapier**, **ENS Domains**, **PostHog**,
  **Postman**, **AsyncAPI**, **CrowdStrike `@crowdstrike/*`**, plus
  `@ctrl/*`, `@nativescript-community/*`, `@teselagen/*`, `angulartics2`,
  `ngx-bootstrap`, `koa2-swagger-ui`, etc.
- Switches from `postinstall` → **`preinstall`** with two-stage loader:
  `setup_bun.js` installs the Bun runtime, then runs `bun_environment.js`
  (~10 MB, heavily obfuscated).
- Persistence via macOS `LaunchAgent` / Linux `systemd` `gh-token-monitor`
  polling GitHub every 60 s.
- Registers victim host as a self-hosted GitHub Actions runner labelled
  **`SHA1HULUD`**.
- Adds a **destructive fallback**: if propagation/exfiltration fail, it
  attempts to wipe `$HOME` (wiper behaviour).
- Exfiltration moved to **`api.masscan.cloud`** and the decentralized
  **Session Protocol** (`getsession.org`) to evade DNS blocking; some
  variants still use the old `webhook.site` UUID.
- **25k+ public GitHub repos** observed leaking secrets via this wave.

**Primary sources:**
- [Microsoft Security Blog — Shai-Hulud 2.0: detection & defense guidance (2025-12-09)](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- [Datadog Security Labs — Shai-Hulud 2.0 npm worm analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Wiz — Sha1-Hulud 2.0 Supply Chain Attack: 25K+ Repos Exposed](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [ReversingLabs — Shai-Hulud 2.0 is spreading. Here's what you need to know](https://www.reversinglabs.com/blog/new-shai-hulud-worm-spreads-what-to-know)
- [Elastic — Navigating the Shai-Hulud Worm 2.0: updated response](https://www.elastic.co/blog/shai-hulud-worm-2-0-updated-response)
- [Netskope — Shai-Hulud 2.0: Aggressive, Automated, Fast Spreading](https://www.netskope.com/blog/shai-hulud-2-0-aggressive-automated-one-of-fastest-spreading-npm-supply-chain-attacks-ever-observed)
- [Mnemonic — Advisory: Shai-Hulud 2.0 supply chain campaign](https://www.mnemonic.io/resources/blog/advisory-shai-hulud-2.0-supply-chain-campaign-rapidly-spreading-through-npm-packages-and-github/)
- [Invicti — Shai-Hulud 2.0 Worm Supply-Chain Attack on npm Dependencies](https://www.invicti.com/blog/web-security/shai-hulud-2-worm-supply-chain-attack-on-npm-dependencies)
- [Orca Security — Shai-Hulud npm Malware: new wave targets 25k+ repos](https://orca.security/resources/blog/shai-hulud-npm-malware-wave-2/)
- [Stream.security — Shai-Hulud 2.0 npm worm: what happened & how we detected it](https://www.stream.security/post/the-shai-hulud-2-0-npm-worm-what-happened-how-stream-detected-it)
- [Reflectiz — Shai-Hulud 2.0: The Worm Returns](https://www.reflectiz.com/blog/shai-hulud-2-0/)
- [Upwind — Shai-Hulud 2: The NPM Supply Chain Attack Returns](https://www.upwind.io/feed/shai-hulud-2-npm-supply-chain-worm-attack)
- [AWS Security Blog — Defending against supply chain attacks like Chalk/Debug and the Shai-Hulud worm](https://aws.amazon.com/blogs/security/defending-against-supply-chain-attacks-like-chalk-debug-and-the-shai-hulud-worm/)
- [Semgrep — NPM Packages Using Secret Scanning Tools to Steal Credentials](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)

### 1.3 Wave 3 — Shai-Hulud 3.0 / enhanced obfuscation (December 2025)

Smaller follow-up wave with rewritten obfuscation, new SHA-256 hashes.
- [Upwind — Shai-Hulud 3.0: npm Supply Chain Worm Reappears With Enhanced Obfuscation](https://www.upwind.io/feed/shai-hulud-3-npm-supply-chain-worm)

### 1.4 Mini Shai-Hulud / TeamPCP (May 2026, cross-ecosystem)

- Self-propagating spread via stolen **CI/CD** secrets and **valid SLSA
  provenance**; affected `@tanstack/*` (incl. `react-router` ≈12M wkly DL),
  `@mistralai/*`, `@uipath/*` (50+), `@squawk/*`, `@tallyui/*`,
  `intercom-client@7.0.4`, `@opensearch-project/opensearch@3.6.2`, plus
  DraftLab. Aikido counts **373 malicious package-versions / 169 names**.
- **Cross-ecosystem jump to PyPI**: `mistralai==2.4.6`, `guardrails-ai==0.10.1`
  (both quarantined by PyPI).
- New malicious file names introduced: `router_init.js`, `setup.mjs`,
  `transformers.pyz`.

**Primary sources:**
- [StepSecurity — Mini Shai-Hulud is back](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
- [Wiz — Mini Shai-Hulud Strikes Again: TanStack + more npm Packages Compromised](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
- [Snyk — TanStack npm Packages Hit by Mini Shai-Hulud](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [BleepingComputer — Shai-Hulud attack ships signed malicious TanStack, Mistral npm packages](https://www.bleepingcomputer.com/news/security/shai-hulud-attack-ships-signed-malicious-tanstack-mistral-npm-packages/)
- [Expel — Mini Shai-Hulud: Cross-ecosystem supply chain worm targeting npm & PyPI](https://expel.com/blog/mini-shai-hulud-cross-ecosystem-supply-chain-worm-targeting-npm-pypi/)
- [The CyberSec Guru — Mini Shai-Hulud npm Attack: All Affected Packages](https://thecybersecguru.com/news/mini-shai-hulud-npm-worm-affected-packages-list/)
- [lilting.ch — Mini Shai-Hulud TanStack npm: 170+ packages, valid SLSA provenance](https://lilting.ch/en/articles/mini-shai-hulud-tanstack-mistral-npm-oidc)
- [CryptoTimes — Mini Shai Hulud Malware Targets Crypto Wallets via npm Packages (2026-05-12)](https://www.cryptotimes.io/2026/05/12/mini-shai-hulud-malware-targets-crypto-wallets-via-npm-packages/)
- [Cybernews — Hundreds of NPM packages compromised in a new supply chain attack](https://cybernews.com/security/npm-packages-with-millions-downloads-compromised/)
- [Red Hat — Multiple Supply Chain Attacks against npm Packages](https://access.redhat.com/security/supply-chain-attacks-NPM-packages)

---

## 2. Indicators of Compromise (consolidated)

### 2.1 Malicious file artifacts (any of these inside a project tree warrants `CRITICAL`)

| Artifact | Wave | Notes |
|---|---|---|
| `bundle.js` (≈3 MB, in root of an installed package) | v1 | Repurposed TruffleHog binary + exfil logic |
| `setup_bun.js` | v2 | Installs Bun runtime |
| `bun_environment.js` (≈10 MB) | v2 | Obfuscated main payload |
| `router_init.js`, `setup.mjs`, `transformers.pyz` | Mini (May 2026) | New TeamPCP loader variants |
| `processor.sh` (in `/tmp` or `node_modules`) | v1 | Branch / workflow stager |
| `migrate-repos.sh` | v1 | Forks private → public `-migration` |
| `data.json` containing double-Base64 blob | v1/v2 | Exfil payload format |
| `cloud.json`, `contents.json`, `environment.json`, `truffleSecrets.json` | v2 | Staging files for TruffleHog output |

### 2.2 SHA-256 hashes (high-confidence, observed in the wild)

```
46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09  bundle.js v1
b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777  variant
dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c  variant
4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db  variant
62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0  bun_environment.js v2
f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068  bun_environment.js v2 variant
cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd  bun_environment.js v2 variant
a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a  setup_bun.js v2
```

Authoritative, updated hash and package lists live in:

- **Datadog IOC repo** (consolidated across vendors):
  - <https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0>
  - Raw CSV (796 confirmed package×version rows):
    <https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv>
- **Cobenian/shai-hulud-detect** (community detector, 2100+ entries, npm+PyPI):
  - <https://github.com/Cobenian/shai-hulud-detect>
  - `compromised-packages.txt` (raw): <https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt>
- **gensecaihq/Shai-Hulud-2.0-Detector** (GitHub Action, SARIF output):
  - <https://github.com/gensecaihq/Shai-Hulud-2.0-Detector>
- **StepSecurity advisories** (rolling) — see §1 link list.
- **Aaron East detection gist** (manual playbook):
  - <https://gist.github.com/aaroneast1/437a310b5e1c0791c46d18f8f5078caa>

### 2.3 GitHub-side IOCs (in account history, not just project tree)

- Public repo named exactly `Shai-Hulud` (description "Shai-Hulud Repository").
- Repo name pattern `<original>-migration` with description `Shai-Hulud Migration`.
- Branch named `shai-hulud` in any owned repo.
- Workflow path `.github/workflows/shai-hulud-workflow.yml`.
- Workflow path `.github/workflows/discussion.yaml` (v2 variant).
- Self-hosted GitHub Actions runner labelled `SHA1HULUD`.
- Any commit referencing the strings above in the message.

### 2.4 Network / host IOCs

- Outbound HTTP to `webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`.
- DNS / HTTPS to `api.masscan.cloud`.
- Session Protocol traffic to `getsession.org` (v2 fallback channel).
- macOS LaunchAgent plist labelled `gh-token-monitor` in
  `~/Library/LaunchAgents/`.
- Linux `gh-token-monitor.service` under `~/.config/systemd/user/` or
  `/etc/systemd/system/`.
- Bun runtime installed in unexpected paths under
  `~/.bun/` on a host that does not otherwise use Bun.

### 2.5 In-package signals

- `preinstall` or `postinstall` script in `package.json` referencing
  `bundle.js`, `setup_bun.js`, `bun_environment.js`, `router_init.js`,
  `setup.mjs`.
- `.npmrc` containing an unexpected auth token (especially with `_authToken`
  that the developer did not set).
- `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` pinning a known
  malicious `name@version` tuple, **even if the package has since been
  unpublished from the registry**.

---

## 3. Auditor design

### 3.1 Goals

- Single-repo Python 3 CLI: `shai-hulud-audit /path/to/project` returns a
  report and a non-zero exit code if any high-severity finding is present.
- Works **offline** with a vendored snapshot of IOC lists; `--update`
  refreshes from upstream feeds.
- Covers **npm and PyPI** ecosystems.
- Audits both the **current tree** and **historical traces** (git history,
  reflog, removed files).
- Output formats: human (default), JSON, SARIF (for CI).
- Zero non-stdlib dependencies for the core scanner; optional `requests` for
  `--update`, optional `yara-python` for bytecode-class matchers.

### 3.2 Detection layers

| # | Layer | Inputs | Detects |
|---|---|---|---|
| 1 | **Lockfile scan** | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lockb` (best-effort), `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock` | Pinned versions matching the compromised list |
| 2 | **Manifest scan** | `package.json`, `pyproject.toml`, `setup.py`, `setup.cfg` | Direct deps in the compromised list (independent of lockfile) |
| 3 | **Installed tree scan** | `node_modules/**`, `.venv/**`, `site-packages/**` | Same as above, plus any installed `bundle.js`, `setup_bun.js`, etc. |
| 4 | **Hash scan** | All files in tree (size-bounded, e.g. >100KB JS/MJS, all `.pyz`) | SHA-256 matches against IOC hash list |
| 5 | **Filename / path scan** | Tree walk | Known malicious filenames (§2.1) anywhere |
| 6 | **Lifecycle script scan** | `package.json` scripts blocks | `preinstall`/`postinstall`/`install` invoking suspicious files |
| 7 | **Git history scan** | `git log -p`, `git reflog`, `git stash list` | Past presence of any IOC artifact, even if removed |
| 8 | **GitHub-side scan** *(optional, `--github`)* | `gh` CLI if available | Repos named `Shai-Hulud`/`*-migration`, branches `shai-hulud`, workflows `shai-hulud-workflow.yml`, runners `SHA1HULUD` |
| 9 | **Host-side scan** *(optional, `--host`)* | `~/Library/LaunchAgents`, systemd user units, `~/.bun`, `~/.npmrc` | Persistence artifacts on the developer machine |
| 10 | **Network-IOC documentation** | n/a | Emits suggested egress rules (no live network monitoring) |

### 3.3 Severity model

| Severity | Trigger | Recommendation |
|---|---|---|
| `CRITICAL` | Hash match, malicious filename present, or installed/locked version exact-matches IOC list | Treat host as **potentially compromised**: rotate every secret reachable from this dev machine, force-push clean lockfile, audit GitHub account |
| `HIGH` | Git history shows a removed IOC artifact, or a previously-locked compromised version (now updated) | Rotate any secret that lived in this repo's CI between the affected timestamps |
| `MEDIUM` | Direct or transitive dependency on a *package* that has *ever* shipped a malicious version (current pinned version is clean) | Verify integrity hash; pin to a post-incident clean release; subscribe to upstream advisories |
| `LOW` | Suspicious lifecycle script naming patterns, but no IOC match | Manual review |
| `INFO` | Bun installed but no other IOC; or `.npmrc` token present | Inventory only |

### 3.4 CLI surface

```
shai-hulud-audit <path>                 # scan a project, exit 1 on HIGH/CRITICAL
  --format human|json|sarif             # default: human
  --output FILE                         # write report (default: stdout)
  --update                              # refresh IOC lists from upstream
  --offline                             # forbid network, fail if lists stale > N days
  --no-git-history                      # skip layer 7
  --github [ORG/USER]                   # enable layer 8 via `gh`
  --host                                # enable layer 9
  --paranoid                            # enable heuristic / typosquat checks
  --since YYYY-MM-DD                    # narrow git-history scan
  --ecosystems npm,pypi                 # default: both
  --ioc-dir PATH                        # override bundled IOC dir
```

Exit codes: `0` clean, `1` HIGH/CRITICAL findings, `2` MEDIUM-only,
`10` tool error.

### 3.5 Report layout

Per finding: `severity • layer • ecosystem • package@version (or path) •
evidence • recommended action • reference URL`. Top of report summarises:
overall verdict, counts per severity, IOC list version + age, scan duration.

JSON schema is documented in `docs/report-schema.json`. SARIF output uses
rule IDs `SHAI-001`..`SHAI-010` mapped to the layers in §3.2.

---

## 4. Repository layout

```
shai_hulud_worm_audit/
├── README.md                # quickstart, usage, false-positive guidance
├── PLAN.md                  # this document
├── LICENSE                  # MIT
├── pyproject.toml           # python ≥ 3.10, console_script entry point
├── shai_hulud_audit/
│   ├── __init__.py
│   ├── __main__.py          # argparse CLI
│   ├── scan/
│   │   ├── lockfiles.py
│   │   ├── manifests.py
│   │   ├── installed.py
│   │   ├── hashes.py
│   │   ├── filenames.py
│   │   ├── lifecycle.py
│   │   ├── git_history.py
│   │   ├── github.py
│   │   └── host.py
│   ├── ioc/
│   │   ├── loader.py        # parse bundled + cached upstream lists
│   │   ├── updater.py       # --update implementation
│   │   └── data/            # vendored snapshots (committed)
│   │       ├── packages_npm.txt
│   │       ├── packages_pypi.txt
│   │       ├── hashes.txt
│   │       ├── filenames.txt
│   │       ├── github_patterns.txt
│   │       └── manifest.json   # source URLs, fetch dates, sha256 of each list
│   ├── report/
│   │   ├── human.py
│   │   ├── json_out.py
│   │   └── sarif.py
│   └── remediation/
│       └── playbook.md      # rendered into --format human at end
├── tests/
│   ├── fixtures/            # tiny synthetic compromised projects
│   ├── test_lockfiles.py
│   ├── test_manifests.py
│   ├── test_hashes.py
│   ├── test_git_history.py
│   └── test_end_to_end.py
├── docs/
│   ├── report-schema.json
│   ├── ioc-sources.md       # provenance table for every list we bundle
│   └── threat-model.md
└── .github/
    └── workflows/
        ├── ci.yml           # tests + lint
        └── ioc-refresh.yml  # weekly scheduled re-fetch + PR
```

Vendored IOC lists are **CSV/TXT with header lines documenting the source
URL and the fetch timestamp**, so provenance is auditable.

---

## 5. Remediation playbook (renders at end of every report with findings)

If the auditor reports `CRITICAL`:

1. **Disconnect the workstation from automated key stores** (`aws sso logout`,
   stop Docker, sign out of GitHub Desktop, kill running `npm`/`pnpm`).
2. **Rotate every credential** reachable from this host (in this order):
   - npm tokens — `npm token revoke <id>` for *all* tokens.
   - GitHub PATs + OAuth apps — revoke at <https://github.com/settings/tokens>
     and <https://github.com/settings/applications>.
   - GitHub Actions secrets and environment secrets in every owned/org repo.
   - AWS access keys (rotate, then `aws iam delete-access-key`).
   - GCP service account keys.
   - Azure client secrets.
   - SSH keys (revoke from GitHub/GitLab/Bitbucket; regenerate locally).
   - Any 1Password / Bitwarden / Vault entries whose values appeared in env.
3. **Audit GitHub account**:
   - Delete repos matching `Shai-Hulud` and `*-migration` (after preserving
     evidence — export issues/code if needed).
   - Delete branches named `shai-hulud` from every repo:
     `for r in $(gh repo list --json name -q .[].name); do gh api repos/:owner/$r/git/refs/heads/shai-hulud -X DELETE 2>/dev/null; done`
   - Remove `.github/workflows/shai-hulud-workflow.yml` and
     `.github/workflows/discussion.yaml` and re-history-rewrite if needed.
   - Inspect the **audit log** (Settings → Security log) for the time
     window starting at first `CRITICAL` evidence.
   - Inspect self-hosted runners; remove any labelled `SHA1HULUD`.
4. **Clean the project tree**:
   - `rm -rf node_modules .venv site-packages bun.lockb`
   - `npm cache clean --force && npm cache verify`
   - `pip cache purge`
   - Pin lockfiles to known-clean versions; rerun install.
5. **Clean the host**:
   - Remove `~/Library/LaunchAgents/*gh-token-monitor*` (macOS) or
     `systemctl --user disable --now gh-token-monitor` (Linux).
   - Remove `~/.bun/` if Bun was never intentionally installed.
   - Re-issue any `.npmrc` `_authToken` lines.
6. **File a report** (CISA / your SOC / the package maintainer).
7. **Subscribe to upstream advisories** so the next wave is caught early:
   GitHub Security Advisories, Socket, Snyk, StepSecurity, Datadog IOC repo.

If the auditor reports `HIGH` only: steps 2–4 still apply but scoped to the
window git-history identifies. `MEDIUM` only: pin away from at-risk
maintainer accounts and enable npm `--ignore-scripts` globally
(`npm config set ignore-scripts true`).

---

## 6. IOC update pipeline

`--update` (and the weekly `ioc-refresh.yml` workflow):

1. Fetch each upstream source listed in `ioc/data/manifest.json`.
2. Validate (CSV header sanity, non-empty, max-size cap).
3. Normalise to internal format (`ecosystem`, `name`, `version`, `source`,
   `first_seen`).
4. Diff against the current bundled snapshot.
5. Write new files; update `manifest.json` (URL, fetched-at, sha256, row
   count).
6. The scheduled workflow opens a PR titled `IOC refresh YYYY-MM-DD` with
   the diff for human review.

Upstream sources (initial set, pinned in `manifest.json`):

| Source | URL | Format |
|---|---|---|
| Datadog consolidated | `https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv` | CSV |
| Datadog wave-2 only | `https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/shai-hulud-2.0.csv` | CSV |
| Cobenian package list | `https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt` | TXT |
| gensecaihq detector | `https://github.com/gensecaihq/Shai-Hulud-2.0-Detector` | repo (pin commit) |
| Snyk advisories (manual ingest) | `https://snyk.io/blog/tanstack-npm-packages-compromised/` etc. | HTML → manual |

---

## 7. Limitations and false positives (documented in `README.md`)

- **Hash-only matches in `node_modules`** can be benign if the package is
  large but legitimate (e.g. a real TruffleHog dev-dep) — the tool
  cross-checks with the filename + lifecycle layers before raising
  `CRITICAL`.
- **A pinned compromised version can be benign** if the package was later
  yanked and replaced *with the same version number* — rare; we still raise
  `HIGH` and instruct the user to verify via `npm view <pkg>@<ver> dist.tarball`
  hash against the GitHub Advisory Database.
- **Git history can be incomplete** on shallow clones; the tool warns when
  `git rev-list --count HEAD` is suspiciously low.
- **The IOC list is never complete.** New waves are still appearing; the
  `--update` channel and weekly PRs are the mitigation.

---

## 8. Milestones

| # | Milestone | Definition of done |
|---|---|---|
| M0 | Plan + repo scaffolding (this PR) | `PLAN.md`, empty package skeleton, MIT license, CI runs `pytest` (no tests yet) |
| M1 | Layers 1–3 (manifest/lockfile/installed) for npm | Detects every Datadog-listed `name@version` in a fixture project; JSON output |
| M2 | Layers 4–6 (hashes, filenames, lifecycle) | All 8 known hashes detected on synthetic fixtures |
| M3 | PyPI support | Mini Shai-Hulud PyPI fixtures (`mistralai==2.4.6`, `guardrails-ai==0.10.1`) flagged |
| M4 | Layer 7 (git history) | Removed `bundle.js` in past commit still detected |
| M5 | `--update` + weekly workflow | PR auto-opens with diff against upstream |
| M6 | Layers 8–9 (`--github`, `--host`) | Find `Shai-Hulud` repo / `shai-hulud` branch / `gh-token-monitor` LaunchAgent on test machine |
| M7 | SARIF output + GitHub Action wrapper | One-line `uses:` block usable in any repo |
| M8 | Remediation playbook + docs polish | `README.md` covers install, run, false-positive triage |
| M9 | 1.0.0 release | Tagged, signed, published to PyPI as `shai-hulud-audit` |

Each milestone is a single PR. No work begins on Mn+1 until Mn merges.

---

## 9. Non-goals

- Not a live network IDS — we document network IOCs but do not capture
  packets.
- Not a generic SCA tool — we *only* hunt for Shai-Hulud / Mini Shai-Hulud
  artifacts; users should still run `npm audit`, Socket, Snyk, Dependabot.
- Not a remediation **executor** — we print the playbook but never
  auto-rotate keys, never auto-delete repos, never `git push`.
- Not Windows-tested in the first release (works under WSL).

---

## 10. Open questions / decisions

- Should bundled IOC lists be in this repo or pulled at install time from a
  sibling `shai-hulud-audit-iocs` repo? Current plan: bundle for offline use,
  small enough (<200 KB compressed).
- Should we ship YARA rules in-tree (optional `--yara` flag)? Add in M2 if
  `yara-python` import is cheap; otherwise punt to v1.1.
- Should we offer a paid hosted scanner endpoint? Out of scope for the OSS
  tool, but the design keeps that door open via the SARIF report format.
