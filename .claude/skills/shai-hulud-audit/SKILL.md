---
name: shai-hulud-audit
description: Audit a codebase for traces of the Shai-Hulud npm/PyPI supply-chain worm (waves v1 Sep 2025, v2 "Second Coming" Nov 2025, v3 Dec 2025, Mini Shai-Hulud cross-ecosystem May 2026). Use when the user asks to "check for Shai-Hulud", "audit npm supply chain", "scan for compromised packages", "check if a project is compromised", "look for malicious lifecycle scripts", or mentions any of: tinycolor compromise, bundle.js/setup_bun.js/bun_environment.js, shai-hulud workflow file, SHA1HULUD runner, gh-token-monitor, the September 2025 chalk/debug crypto-theft attack, or supply-chain worm in npm/PyPI. Also trigger when the user wants to verify CI/dev hosts have not been infected by the worm.
tools: Bash, Read, Glob, Grep, Edit
---

# Shai-Hulud Worm Audit

Audit a project (and optionally the developer host) for present or historical
traces of the **Shai-Hulud** self-replicating supply-chain worm. The worm has
shipped in four waves so far (Sep 2025, Nov 2025, Dec 2025, May 2026 cross-
ecosystem), compromising **800+ npm packages** and **2,100+ package×version
tuples** including `@ctrl/tinycolor`, `chalk@5.6.1`, `@crowdstrike/*`,
`@tanstack/react-router`, `mistralai`, `guardrails-ai`, and many more.

**Authoritative reference**: <https://github.com/PQCWorld/shai_hulud_worm_audit>
— companion CLI tool, full IOC dataset, and remediation playbook.

---

## When to invoke

Trigger on any of:

- User asks to "audit", "scan", "check" a project for supply-chain compromise,
  malware, the Shai-Hulud worm, npm worm, or compromised packages.
- User mentions a specific Shai-Hulud IOC: `bundle.js`, `setup_bun.js`,
  `bun_environment.js`, `shai-hulud-workflow.yml`, `SHA1HULUD`,
  `gh-token-monitor`, `@ctrl/tinycolor` 4.1.1/4.1.2, `chalk@5.6.1`,
  `mistralai==2.4.6`.
- User asks "is my project safe to install / build / publish?" after the
  September 2025 or November 2025 incidents.
- A `npm install` / `pip install` produced unexpected output, postinstall
  warnings, or unexpected network egress.

## Workflow

### Phase 1 — Locate target

Confirm the target path. If the user did not specify one, default to the
current working directory:

```bash
pwd
ls -la
```

Look for ecosystem signals so you know which checks matter:

```bash
ls -la package.json package-lock.json yarn.lock pnpm-lock.yaml \
       requirements*.txt poetry.lock Pipfile.lock pyproject.toml 2>/dev/null
```

### Phase 2 — Prefer the CLI if installed

If the user has the companion tool installed, use it — it has the canonical
2,139-entry IOC dataset, 16 hashes, 20 filenames, and emits an exit code that
encodes severity:

```bash
which shai-hulud-audit && shai-hulud-audit --version
```

If available, run:

```bash
shai-hulud-audit --format human <PATH>
# or for CI / piping:
shai-hulud-audit --format json <PATH>
# Add --host to scan the developer machine for persistence artifacts:
shai-hulud-audit --host <PATH>
```

**Exit codes**: `0` clean/info-only, `1` HIGH or CRITICAL findings present,
`10` tool error. The human report includes the full remediation playbook in
its tail when findings exist.

If the CLI is not installed, ask the user whether to:

1. Install it: `pip install git+https://github.com/PQCWorld/shai_hulud_worm_audit`
2. Clone and run in place: `git clone https://github.com/PQCWorld/shai_hulud_worm_audit /tmp/sh-audit && /tmp/sh-audit/.venv/bin/pip install -e /tmp/sh-audit && /tmp/sh-audit/.venv/bin/shai-hulud-audit <PATH>`
3. Proceed with the manual fallback in Phase 3.

### Phase 3 — Manual fallback (when the CLI is unavailable)

Run each check below. Report findings with **severity, evidence, file path,
and recommendation**. Severity convention is the same as the CLI:

- **CRITICAL** — installed/locked compromised exact version, payload-name
  file in the tree, hash match, or lifecycle script invoking a payload.
- **HIGH** — historical (git) trace of any IOC; branch `shai-hulud`.
- **MEDIUM** — dependency on a package that has *ever* shipped a malicious
  version (resolved version may still be clean — verify).
- **LOW / INFO** — generic indicators worth recording but not actionable
  on their own.

#### 3.1 Malicious filenames in the working tree

```bash
find . -type f \( \
    -name bundle.js -o -name setup_bun.js -o -name bun_environment.js -o \
    -name bun_installer.js -o -name router_init.js -o -name tanstack_runner.js -o \
    -name transformers.pyz -o -name processor.sh -o -name migrate-repos.sh -o \
    -name shai-hulud-workflow.yml -o -name discussion.yaml -o \
    -name gh-token-monitor.sh -o -name 'com.user.gh-token-monitor.plist' -o \
    -name gh-token-monitor.service -o -name truffleSecrets.json \
  \) -not -path '*/node_modules/.cache/*' 2>/dev/null
```

**Interpretation**:

- `setup_bun.js`, `bun_environment.js`, `bun_installer.js`,
  `router_init.js`, `tanstack_runner.js`, `transformers.pyz`,
  `gh-token-monitor.*`, `truffleSecrets.json`, `shai-hulud-workflow.yml`:
  **CRITICAL on sight, regardless of location.**
- `bundle.js`: **CRITICAL** only if also referenced by a lifecycle script
  (see 3.4); otherwise **MEDIUM** (often a legitimate webpack output). A
  `bundle.js` deep inside `node_modules/<pkg>/scripts/` is almost always
  legitimate — downgrade to INFO unless the package name is on the
  compromised list.

#### 3.2 SHA-256 hash check for the known payloads

These hashes have been observed in the wild across the four waves. Compute
SHA-256 over any `*.js`, `*.mjs`, `*.pyz`, `*.sh`, `*.yml`, `*.json`, or
`*.plist` file ≥1 KB and compare:

```
46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09
b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777
dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c
4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db
62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0
f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068
cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd
a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a
de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6
81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3
83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e
86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b
aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee
ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c
2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96
7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b
```

One-liner (any match is **CRITICAL**, regardless of path):

```bash
HASHES=$(cat <<'EOF'
46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09
b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777
dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c
4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db
62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0
f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068
cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd
a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a
de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6
81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3
83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e
86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b
aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee
ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c
2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96
7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b
EOF
)
find . -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.pyz' \
                  -o -name '*.sh' -o -name '*.yml' -o -name '*.yaml' \
                  -o -name '*.plist' -o -name '*.json' \) \
       -size +1k -size -100M -not -path '*/.git/*' 2>/dev/null \
  | xargs -I{} shasum -a 256 {} 2>/dev/null \
  | grep -F -f <(echo "$HASHES")
```

#### 3.3 Compromised package×version pairs

Fetch the canonical 2,100+ entry list and grep it against this project's
lockfiles and manifests:

```bash
# Fetch the maintained list (cache /tmp on subsequent runs)
test -f /tmp/sh-iocs.txt || curl -sSL \
  https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt \
  -o /tmp/sh-iocs.txt

# Normalise to "name@version"
awk -F: '!/^#/ && NF >= 2 {
    if (NF==2) { print $1 "@" $2 }
    else if ($1=="npm" || $1=="pypi") { sub(/^[^:]*:/, ""); n=split($0,p,":"); print p[1] "@" p[n] }
}' /tmp/sh-iocs.txt | sort -u > /tmp/sh-iocs.normalised
```

Then, for each ecosystem found in Phase 1:

**npm**:

```bash
# Lockfile pinned versions (CRITICAL on match)
grep -h -E '"(name|version)":' package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
# Or better — read with jq if package-lock.json exists:
jq -r '.packages // {} | to_entries[] | "\(.value.name // (.key|sub("^node_modules/";""))) @ \(.value.version // "?")"' package-lock.json 2>/dev/null \
  | sed 's/ @ /@/' | sort -u > /tmp/sh-installed.npm
comm -12 /tmp/sh-installed.npm <(grep -v '^pypi:' /tmp/sh-iocs.normalised | sort)
```

**PyPI**:

```bash
# requirements*.txt: pinned == lines
grep -hE '^\s*[A-Za-z0-9_.\-]+\s*==' requirements*.txt 2>/dev/null \
  | sed -E 's/\s*==\s*/@/;s/\s*#.*//' | tr -d ' ' > /tmp/sh-installed.pypi
# Pipfile.lock / poetry.lock: read with jq / regex
comm -12 /tmp/sh-installed.pypi <(grep '^pypi:' /tmp/sh-iocs.normalised \
  | sed 's|^pypi:||' | sort)
```

**Interpretation**:

- An exact-pin hit (`name@version`) in a lockfile or manifest is **CRITICAL**.
- A range-spec (e.g. `^5.4.0`) where one of the matched versions falls within
  the range is **MEDIUM** — the resolved version *might* be the malicious
  one. Verify with `npm ls <pkg>` or `jq` on the lockfile.

#### 3.4 Lifecycle script analysis

```bash
# Project's own package.json — any preinstall/install/postinstall that
# references a payload basename is CRITICAL.
jq -r '.scripts // {} | to_entries[] | "\(.key): \(.value)"' package.json 2>/dev/null \
  | grep -E 'bundle\.js|setup_bun\.js|bun_environment\.js|router_init\.js|setup\.mjs|tanstack_runner\.js|transformers\.pyz'

# Same check across every installed dep (slower):
find node_modules -name package.json -not -path '*/node_modules/.cache/*' 2>/dev/null \
  | while read f; do
      jq -r '. as $p | .scripts // {} | to_entries[]
             | select(.key|test("install|prepare|prepublishOnly"))
             | "\($p.name)@\($p.version) \(.key): \(.value)"' "$f" 2>/dev/null
    done \
  | grep -E 'bundle\.js|setup_bun\.js|bun_environment\.js|router_init\.js|setup\.mjs|tanstack_runner\.js|transformers\.pyz'
```

#### 3.5 Git history & branches

```bash
# Branch named shai-hulud anywhere — CRITICAL
git for-each-ref --format='%(refname:short)' refs/heads refs/remotes 2>/dev/null \
  | grep -E '(^|/)shai-hulud$'

# Filename ever committed (HIGH even if since deleted)
for name in bundle.js setup_bun.js bun_environment.js router_init.js \
            setup.mjs transformers.pyz processor.sh migrate-repos.sh \
            shai-hulud-workflow.yml discussion.yaml gh-token-monitor.sh \
            truffleSecrets.json; do
  hits=$(git log --all --pretty=format:%H --diff-filter=A -- "**/$name" "$name" 2>/dev/null | head -1)
  [ -n "$hits" ] && echo "git history shows $name (first commit $hits)"
done
```

#### 3.6 GitHub-account artifacts (optional, requires `gh` CLI)

```bash
gh repo list --limit 1000 --json name,description \
  | jq -r '.[] | select(
      (.name == "Shai-Hulud") or
      (.description // "" | test("Shai-Hulud Repository|Sha1-Hulud|Shai-Hulud Migration")) or
      (.name | endswith("-migration"))
    ) | .name'
```

Any output here is **CRITICAL**. Investigate via the audit log:
<https://github.com/settings/security-log>.

#### 3.7 Host persistence (optional, only with user consent)

```bash
ls -la ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null   # macOS
ls -la ~/.config/systemd/user/gh-token-monitor.service 2>/dev/null          # Linux
ls -la /etc/systemd/system/gh-token-monitor.service 2>/dev/null
ls -la ~/.bun 2>/dev/null    # legitimate if you use Bun; suspicious otherwise
```

### Phase 4 — Report findings

Output a structured report. Lead with the **verdict**, then enumerate
findings grouped by severity, then attach the remediation playbook **only if
CRITICAL or HIGH** findings exist.

**Verdict labels**:

- `CLEAN` — no IOCs detected.
- `COMPROMISE INDICATORS PRESENT` — at least one CRITICAL or HIGH finding.
  Act on the playbook below.
- `AT-RISK` — MEDIUM findings only. Pin away from at-risk maintainers and
  verify resolved versions.
- `LOW-NOISE` — only INFO findings.

**Per-finding format** (mirror the CLI for consistency):

```
[SHAI-NNN] <layer> <package@version|path>
    evidence   : <one-line evidence>
    do         : <recommended action>
    reference  : https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#…
```

Rule IDs:

| ID | Layer |
|---|---|
| SHAI-001 | Lockfile pins compromised package |
| SHAI-002 | Manifest references compromised package |
| SHAI-003 | Installed package matches compromised version |
| SHAI-004 | File hash matches known Shai-Hulud payload |
| SHAI-005 | Known Shai-Hulud filename present |
| SHAI-006 | Lifecycle script invokes Shai-Hulud payload |
| SHAI-007 | Git history contains Shai-Hulud artifact |
| SHAI-008 | GitHub account contains Shai-Hulud artifact |
| SHAI-009 | Host persistence artifact present |

### Phase 5 — Remediation playbook (only if CRITICAL/HIGH/MEDIUM present)

Walk the user through, in this order. **Do not auto-execute destructive
commands** — show them and confirm.

1. **Disconnect automated key stores**: `aws sso logout`; stop Docker; sign
   out of GitHub Desktop; kill running `npm`/`pnpm`/`pip`.
2. **Rotate every credential** reachable from this host, in this order:
   - npm tokens: `npm token list` → `npm token revoke <id>` for each.
   - GitHub PATs: revoke at <https://github.com/settings/tokens> and OAuth
     apps at <https://github.com/settings/applications>. Then re-issue.
   - Repo & org Actions secrets and environment secrets.
   - AWS keys: `aws iam list-access-keys` → rotate then delete.
   - GCP service-account keys.
   - Azure client secrets.
   - SSH keys (revoke from GitHub/GitLab; regenerate locally).
   - 1Password / Bitwarden / Vault entries whose values ever appeared in env.
3. **Audit GitHub account**:
   - Delete repos named `Shai-Hulud` and `*-migration` (preserve evidence
     first if needed).
   - For every owned repo, delete branch `shai-hulud`:
     ```bash
     for r in $(gh repo list --json name -q '.[].name'); do
       gh api "repos/:owner/$r/git/refs/heads/shai-hulud" -X DELETE 2>/dev/null
     done
     ```
   - Remove `.github/workflows/shai-hulud-workflow.yml` and
     `.github/workflows/discussion.yaml` from any owned repo; rewrite history
     with `git filter-repo` if needed.
   - Inspect Settings → Security log for the affected window.
   - Remove self-hosted runners labelled `SHA1HULUD`.
4. **Clean the project tree**:
   ```bash
   rm -rf node_modules .venv site-packages bun.lockb
   npm cache clean --force && npm cache verify
   pip cache purge
   # Pin lockfiles to known-clean versions; reinstall.
   ```
5. **Clean the host** (with user consent):
   ```bash
   # macOS
   launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist 2>/dev/null
   rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
   # Linux
   systemctl --user disable --now gh-token-monitor 2>/dev/null
   rm -f ~/.config/systemd/user/gh-token-monitor.service
   # If Bun was never installed by you:
   rm -rf ~/.bun
   ```
6. **Report**: file an incident with the user's SOC if applicable, and
   notify package maintainers via GitHub Security Advisories.
7. **Subscribe** to upstream advisories so the next wave is caught early:
   - <https://github.com/DataDog/indicators-of-compromise>
   - <https://github.com/Cobenian/shai-hulud-detect>
   - <https://www.stepsecurity.io/blog>
   - <https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem>

---

## False-positive guidance

- **`bundle.js` in `node_modules/<legit-pkg>/`** is almost always a webpack
  build artifact. Cross-check with 3.2 (hash) and 3.4 (lifecycle); only
  escalate above MEDIUM if either confirms.
- **A lockfile that pins a compromised exact version** can still be safe if
  the registry republished the same version with cleaned content. Verify by
  hashing the tarball:
  ```bash
  npm view <pkg>@<ver> dist.tarball
  curl -sL "$URL" | shasum -a 256
  # Compare against npm's recorded dist.integrity field.
  ```
- **`~/.bun` exists** is legitimate if the user installed Bun deliberately;
  treat as INFO and ask before recommending removal.
- **Shallow git clones** miss history. If `git rev-list --count HEAD` is
  suspiciously low (e.g. 1–2 on a long-lived project), tell the user the
  history check is incomplete.

## What NOT to do

- **Never** run `git push --force`, `rm -rf node_modules`, `npm cache clean`,
  or any credential rotation **without explicit user confirmation**.
- **Never** auto-delete a GitHub repo, branch, or workflow — show the
  command and confirm.
- **Never** claim a project is clean without running at least 3.1
  (filenames), 3.3 (versions) and 3.4 (lifecycle).
- **Never** invent hashes, package names, or vendor names not present in the
  IOC dataset shipped with this skill.

## References

Detailed threat background, all four waves, full IOC tables, and
verifiable vendor links live in
<https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md>.

Primary writeups:

- CISA Alert (2025-09-23): <https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem>
- Unit 42 / Palo Alto: <https://unit42.paloaltonetworks.com/npm-supply-chain-attack/>
- Microsoft (Dec 2025) — Shai-Hulud 2.0: <https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/>
- Datadog Security Labs: <https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/>
- Wiz: <https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack>
- StepSecurity (Mini Shai-Hulud): <https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem>
- AWS Security: <https://aws.amazon.com/blogs/security/defending-against-supply-chain-attacks-like-chalk-debug-and-the-shai-hulud-worm/>
