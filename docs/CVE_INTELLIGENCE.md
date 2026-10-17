# CVE Intelligence

Open it from **Patch & CVE > AI Fix CVEs**. Implementation: `src/engines/cve_intel_core.h` (portable, unit-tested) and `cve_intel_engine.h` (Windows).

## Pipeline
1. **Inventory** - installed applications from the registry (name, publisher, version, executable).
2. **Intelligence** - the CISA *Known Exploited Vulnerabilities* catalog (one download, cached 24 h) and NVD 2.0 records, cached in `%APPDATA%\Kaevex\cve_cache.bin`.
   NVD allows ~5 requests / 30 s without a key; set the `NVD_API_KEY` environment variable for ~10x faster scans.
3. **Matching** - KEV entries propose *candidates*; the NVD record is then checked against the **installed version** using its CPE ranges
   (`versionStart/End Including/Excluding`, exact versions). Product-name matching is heuristic, so every finding carries a confidence
   (HIGH / MEDIUM / LOW). Examples handled: "Visual Studio Code" is *not* `visual_studio`; generic products such as "windows" never match; unknown versions are never flagged.
4. **AI plan** - the selected AI provider receives the CVE facts and a *closed list* of installed winget package IDs (from `winget export`) and must answer with JSON:
   `UPGRADE_WINGET` (only an ID from that list), `CONTAIN_NETWORK`, `MANUAL` or `NONE`. Anything else - free text commands, unknown IDs, injected text from CVE descriptions - is rejected. Without AI, a deterministic rule-based plan is used.
5. **Enforcement** - `winget upgrade --id <ID> --exact --silent` (no shell), or a Windows Firewall block rule with a 90 s confirm-or-rollback safety net. Network containment is never automatic and never counts as "fixed".
6. **Verification** - the registry is re-read and the CVE re-evaluated. Only then is the finding **FIXED (verified)**. "Re-verify" repeats this after manual updates.

## Limits
- NVD/CPE data can be incomplete or wrong; a match is evidence, not proof. LOW confidence findings are never patched automatically.
- Windows OS updates (KBs) are not evaluated.
- Applications that do not register a version in the Uninstall registry keys cannot be matched.
- Portable apps and software not listed in the registry are invisible to the scan.
