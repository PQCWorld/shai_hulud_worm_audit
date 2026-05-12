"""Human-readable report writer."""

from __future__ import annotations

from collections.abc import Iterable

from ..findings import Finding, Severity

_PLAYBOOK = """\
REMEDIATION PLAYBOOK
====================
If any finding above is CRITICAL, treat this workstation/CI host as potentially
compromised. Work in this order:

  1. Disconnect automated key stores (aws sso logout, stop Docker, sign out
     of GitHub Desktop). Stop any running npm/pnpm/pip processes.
  2. Rotate every credential reachable from this host, in this order:
       - npm token revoke  (all tokens)
       - revoke GitHub PATs, OAuth apps, and Actions/environment secrets
       - rotate AWS access keys (iam delete-access-key)
       - rotate GCP service-account keys
       - rotate Azure client secrets
       - regenerate SSH keys (re-add to GitHub / GitLab)
       - rotate anything in 1Password / Bitwarden / Vault that lived in env
  3. Audit GitHub account:
       - delete repos named "Shai-Hulud" and "*-migration"
       - for r in $(gh repo list --json name -q .[].name); do
           gh api repos/:owner/$r/git/refs/heads/shai-hulud -X DELETE 2>/dev/null
         done
       - remove .github/workflows/shai-hulud-workflow.yml and discussion.yaml
       - inspect Settings -> Security log for the affected window
       - remove self-hosted runners labelled SHA1HULUD
  4. Clean the project tree:
       rm -rf node_modules .venv site-packages bun.lockb
       npm cache clean --force && npm cache verify
       pip cache purge
       pin lockfiles to known-clean versions
  5. Clean the host (macOS):
       rm -f ~/Library/LaunchAgents/com.user.gh-token-monitor.plist
       rm -rf ~/.bun                                    # if never installed by you
  6. Report (CISA / your SOC / package maintainer).
  7. Subscribe to upstream advisories so the next wave is caught early:
       - https://github.com/DataDog/indicators-of-compromise
       - https://github.com/Cobenian/shai-hulud-detect
       - https://www.stepsecurity.io/blog
"""


def write(findings: Iterable[Finding], buf, *, ioc_summary: str = "") -> None:
    findings = sorted(findings, key=lambda f: (-int(f.severity), f.layer, str(f.path or "")))

    by_sev: dict[Severity, list[Finding]] = {s: [] for s in Severity}
    for f in findings:
        by_sev[f.severity].append(f)

    total = len(findings)
    crit = len(by_sev[Severity.CRITICAL])
    high = len(by_sev[Severity.HIGH])
    med = len(by_sev[Severity.MEDIUM])
    low = len(by_sev[Severity.LOW])
    info = len(by_sev[Severity.INFO])

    if total == 0:
        verdict = "CLEAN — no Shai-Hulud IOCs detected."
    elif crit or high:
        verdict = "COMPROMISE INDICATORS PRESENT — act on the playbook below."
    elif med:
        verdict = "AT-RISK — pin away from compromised maintainers; verify resolved versions."
    else:
        verdict = "LOW-NOISE — informational findings only."

    print("=" * 72, file=buf)
    print("Shai-Hulud Worm Audit Report", file=buf)
    print("=" * 72, file=buf)
    print(f"Verdict     : {verdict}", file=buf)
    print(
        f"Findings    : {total} total  "
        f"(critical={crit} high={high} medium={med} low={low} info={info})",
        file=buf,
    )
    if ioc_summary:
        print(f"IOC dataset : {ioc_summary}", file=buf)
    print("", file=buf)

    if findings:
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            items = by_sev[sev]
            if not items:
                continue
            print(f"--- {sev.label} ({len(items)}) " + "-" * (72 - 6 - len(sev.label) - len(str(len(items)))), file=buf)
            for f in items:
                pkg = f"{f.package}@{f.version}" if f.package and f.version else (f.package or "")
                pkg_str = f" {pkg}" if pkg else ""
                print(f"[{f.rule_id}] {f.layer}{pkg_str}", file=buf)
                if f.path:
                    print(f"    path       : {f.path}", file=buf)
                print(f"    evidence   : {f.evidence}", file=buf)
                if f.recommendation:
                    print(f"    do         : {f.recommendation}", file=buf)
                if f.reference:
                    print(f"    reference  : {f.reference}", file=buf)
                print("", file=buf)

    if crit or high or med:
        print("", file=buf)
        print(_PLAYBOOK, file=buf)
