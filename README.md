# shai-hulud-audit

A Python 3 CLI that audits a project for traces of the **Shai-Hulud** npm/PyPI
self-replicating supply-chain worm (waves v1 Sep 2025, v2 "Second Coming" Nov 2025,
v3 Dec 2025, Mini Shai-Hulud cross-ecosystem May 2026).

Reads vendored IOC snapshots from Datadog and the Cobenian community detector,
covers ten detection layers, emits human / JSON / SARIF reports, and ships a
remediation playbook for every finding.

> **Scope.** Single-repo CLI tool. For threat background and the full plan, see
> [`PLAN.md`](PLAN.md).

## Install

```bash
pip install -e .          # from a clone
pip install -e ".[update]" # adds `requests` for `--update`
pip install -e ".[dev]"   # adds pytest + ruff
```

Requires Python ≥ 3.10. Works on macOS and Linux (Windows: WSL).

## Quickstart

```bash
shai-hulud-audit .                                # scan current directory
shai-hulud-audit /path/to/project                 # scan a specific tree
shai-hulud-audit --format json /path/to/project   # JSON output
shai-hulud-audit --format sarif . > audit.sarif   # SARIF for CI / GH code-scanning
shai-hulud-audit --host /path/to/project          # also scan host for persistence
shai-hulud-audit --github /path/to/project        # also probe GitHub via `gh` CLI
shai-hulud-audit --update                         # refresh IOC lists from upstream
```

**Exit codes**: `0` clean / informational only, `1` HIGH or CRITICAL findings
(default threshold; use `--fail-on medium` to widen), `10` tool error.

## Example audits

### A clean project

```text
$ shai-hulud-audit --no-git-history ~/code/acme-web
========================================================================
Shai-Hulud Worm Audit Report
========================================================================
Verdict     : CLEAN — no Shai-Hulud IOCs detected.
Findings    : 0 total  (critical=0 high=0 medium=0 low=0 info=0)
IOC dataset : 2139 packages, 16 hashes, 20 filenames

$ echo $?
0
```

### A project that depends on a once-compromised package (MEDIUM)

`chalk@5.6.1` was published as malicious during the Sep 8 2025 "chalk/debug
crypto-theft" attack. A manifest that requests `^5.4.0` may resolve to
`5.6.1` on install.

```text
$ shai-hulud-audit --no-git-history ~/code/acme-cli
========================================================================
Shai-Hulud Worm Audit Report
========================================================================
Verdict     : AT-RISK — pin away from compromised maintainers; verify resolved versions.
Findings    : 1 total  (critical=0 high=0 medium=1 low=0 info=0)
IOC dataset : 2139 packages, 16 hashes, 20 filenames

--- MEDIUM (1) -----------------------------------------------------------
[SHAI-002] manifest chalk
    path       : /home/dev/code/acme-cli/package.json
    evidence   : dependencies.chalk spec='^5.4.0'; compromised versions: ['5.6.1']
    do         : Verify your resolved version is post-incident. Pin to a known-clean release
                 and enable `npm config set ignore-scripts true` on shared machines.
    reference  : https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#22-sha-256-hashes-high-confidence-observed-in-the-wild

$ echo $?
0        # default --fail-on=high: MEDIUM does NOT trip exit code
$ shai-hulud-audit --no-git-history --fail-on medium ~/code/acme-cli ; echo $?
…
1
```

What to do next: open the project's lockfile, find the resolved version of
`chalk`, and confirm it is not `5.6.1`:

```bash
jq -r '.packages | to_entries[] | select(.key|test("chalk")) | "\(.key) -> \(.value.version)"' package-lock.json
# or
npm ls chalk
```

If the resolved version is the malicious one, follow the playbook in step 4
of the report.

### A directly compromised lockfile (CRITICAL)

```text
$ shai-hulud-audit --no-git-history ~/code/acme-monorepo
========================================================================
Shai-Hulud Worm Audit Report
========================================================================
Verdict     : COMPROMISE INDICATORS PRESENT — act on the playbook below.
Findings    : 2 total  (critical=2 high=0 medium=0 low=0 info=0)
IOC dataset : 2139 packages, 16 hashes, 20 filenames

--- CRITICAL (2) ---------------------------------------------------------
[SHAI-001] lockfile @ctrl/tinycolor@4.1.2
    path       : /home/dev/code/acme-monorepo/package-lock.json
    evidence   : node_modules/@ctrl/tinycolor -> @ctrl/tinycolor@4.1.2
    do         : Remove the lockfile and node_modules/.venv, pin to a known-clean version,
                 rotate every credential reachable from CI/dev machines that ran an install.
    reference  : …

[SHAI-006] lifecycle
    path       : /home/dev/code/acme-monorepo/node_modules/@ctrl/tinycolor/package.json
    evidence   : postinstall: 'node bundle.js' (matches bundle.js)
    do         : Remove the script entry, delete the referenced file, treat the host as
                 compromised, and rotate credentials.
    reference  : …

…(full remediation playbook follows)…

$ echo $?
1
```

### Hash + filename + git-history finding (Mini Shai-Hulud)

```text
$ shai-hulud-audit ~/code/acme-tools
…
--- CRITICAL (3) ---------------------------------------------------------
[SHAI-004] hash
    path       : /home/dev/code/acme-tools/scripts/setup.mjs
    evidence   : sha256=a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a
                 (hint=setup_bun.js, wave=v2)
    …

[SHAI-005] filename
    path       : /home/dev/code/acme-tools/transformers.pyz
    evidence   : … (wave=mini)
    …

[SHAI-007] git_history
    path       : /home/dev/code/acme-tools
    evidence   : 4 commit(s) touched **/bun_environment.js; first 9d2a1c7b…, last c1f307aa…
    …
```

### JSON / SARIF output

```bash
# JSON for tooling
shai-hulud-audit --format json ~/code/acme-web > audit.json
jq '.summary' audit.json

# SARIF for GitHub code-scanning upload
shai-hulud-audit --format sarif ~/code/acme-web > audit.sarif
gh api repos/:owner/:repo/code-scanning/sarifs -F sarif=@audit.sarif ...
```

### As a CI gate

```yaml
# .github/workflows/audit.yml
name: Shai-Hulud audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install git+https://github.com/PQCWorld/shai_hulud_worm_audit
      - run: shai-hulud-audit --fail-on high --format sarif . > audit.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: audit.sarif }
```

## Detection layers

| ID | Layer | What it checks |
|---|---|---|
| SHAI-001 | Lockfiles | `package-lock.json` (v1/v2/v3), `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock` |
| SHAI-002 | Manifests | `package.json`, `pyproject.toml`, `setup.py`, `setup.cfg` |
| SHAI-003 | Installed tree | `node_modules/**/package.json`, `site-packages/**/METADATA` |
| SHAI-004 | File hashes | SHA-256 of `.js/.mjs/.pyz/.sh/.yml/.json/.plist` vs IOC hash list |
| SHAI-005 | Filenames | Known basenames (`bundle.js`, `setup_bun.js`, `bun_environment.js`, `router_init.js`, `tanstack_runner.js`, `setup.mjs`, `transformers.pyz`, `processor.sh`, `migrate-repos.sh`, `gh-token-monitor.*`) |
| SHAI-006 | Lifecycle scripts | npm `preinstall`/`postinstall`/`install` invoking any payload filename |
| SHAI-007 | Git history | `git log --all` for any IOC filename; branch named `shai-hulud`; malicious workflow paths in history |
| SHAI-008 | GitHub account *(opt-in `--github`)* | Repos named `Shai-Hulud`, `*-migration` with Shai-Hulud description, `shai-hulud` branches anywhere |
| SHAI-009 | Host *(opt-in `--host`)* | macOS LaunchAgent / Linux systemd `gh-token-monitor`, `~/.bun` if unexpected, `~/.npmrc` tokens |
| SHAI-010 | Network IOCs *(documented)* | `webhook.site/bb8ca5f6-…`, `api.masscan.cloud`, `getsession.org` |

## Severity model

- **CRITICAL** — hash match, malicious filename, installed/locked compromised
  version, lifecycle script invoking a payload, GitHub exfil repo / branch,
  host persistence artifact. Treat host as compromised; rotate everything.
- **HIGH** — historical (git-history) IOC artifact; rotate any secret that was
  live in CI between the first and last commit timestamps.
- **MEDIUM** — direct or transitive dependency on a *package* that has *ever*
  shipped a compromised version (current pin is clean). Verify resolved
  version; pin away from the at-risk maintainer.
- **LOW / INFO** — suspicious lifecycle script naming, Bun installed but
  otherwise clean, `.npmrc` token present. Inventory only.

## False-positive guidance

- `bundle.js` is a common webpack output. Layer 5 reports it as **MEDIUM**
  unless layer 6 sees a lifecycle script that actually invokes it.
- A pinned compromised version *can* be benign if the registry republished
  the same version number with cleaned content. Verify via:
  ```bash
  npm view <pkg>@<ver> dist.tarball  # then sha256 the tarball
  ```
- `~/.bun/` is legitimate if you use Bun. The `--host` finding is INFO; treat
  it as evidence only when paired with another finding.
- Shallow clones miss git history. The tool warns when `git rev-list --count
  HEAD` is unusually low.

## Updating IOC lists

```bash
shai-hulud-audit --update                  # refresh in place
shai-hulud-audit --update --ioc-dir DIR    # refresh a private mirror
```

Upstream sources are pinned in
[`shai_hulud_audit/ioc/data/manifest.json`](shai_hulud_audit/ioc/data/manifest.json):

- [Datadog IOC repo (Apache-2.0)](https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0)
  — consolidated wave-2 packages, 796 confirmed.
- [Cobenian/shai-hulud-detect (MIT)](https://github.com/Cobenian/shai-hulud-detect)
  — community-maintained 2,100+ entries spanning Sep 2025 – May 2026 across npm + PyPI.

A weekly GitHub Actions workflow ([`.github/workflows/ioc-refresh.yml`](.github/workflows/ioc-refresh.yml))
opens a PR with the diff whenever upstream feeds change.

## Remediation playbook

The human-format report appends the playbook automatically whenever any
HIGH/CRITICAL/MEDIUM finding is present. The short version, for reference:

1. **Disconnect automated key stores** (`aws sso logout`, sign out of GitHub
   Desktop, stop running `npm`/`pip`).
2. **Rotate every credential** reachable from this host, in this order:
   npm tokens → GitHub PATs/OAuth/Actions secrets → AWS keys → GCP service
   accounts → Azure secrets → SSH keys → vault/1Password entries.
3. **Audit GitHub account**: delete repos named `Shai-Hulud` / `*-migration`;
   delete `shai-hulud` branches; remove `shai-hulud-workflow.yml` and
   `discussion.yaml`; inspect Settings → Security log; remove self-hosted
   runners labelled `SHA1HULUD`.
4. **Clean the project**: `rm -rf node_modules .venv site-packages`, clean
   caches, pin lockfiles to known-clean versions, reinstall.
5. **Clean the host**: remove `~/Library/LaunchAgents/*gh-token-monitor*`
   (macOS) or the equivalent systemd user unit; remove `~/.bun` if it was not
   installed intentionally.
6. **Report** to CISA / your SOC / the package maintainer.
7. **Subscribe** to upstream advisories so the next wave is caught early.

The full playbook lives in [`PLAN.md` §5](PLAN.md#5-remediation-playbook-renders-at-end-of-every-report-with-findings).

## References

All vendor writeups with verifiable links are listed in [`PLAN.md` §1](PLAN.md#1-threat-background-verifiable-references).
Highlights:

- [CISA Alert (Sep 2025)](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [Unit 42 / Palo Alto Networks](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Microsoft (Dec 2025) — Shai-Hulud 2.0 guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/)
- [Wiz](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- [Sysdig](https://www.sysdig.com/blog/shai-hulud-the-novel-self-replicating-worm-infecting-hundreds-of-npm-packages)
- [StepSecurity (Mini Shai-Hulud)](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
- [AWS Security blog](https://aws.amazon.com/blogs/security/defending-against-supply-chain-attacks-like-chalk-debug-and-the-shai-hulud-worm/)

## License

MIT — see [`LICENSE`](LICENSE). Vendored IOC data retains its upstream license
(Apache-2.0 for Datadog, MIT for Cobenian) — see `manifest.json` for provenance.
