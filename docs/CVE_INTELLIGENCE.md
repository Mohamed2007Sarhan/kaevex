# CVE detection and remediation status

The CVE view inventories installed Windows applications from the registry and reads OS build metadata. Its bundled application and OS CVE catalogs were cleared because the entries were unverified and included unrelated-product matches. A catalog match, when present, remains a candidate rather than proof; installed KB state is not verified.

The GUI can fetch NVD 2.0 CVEs published in the preceding seven days using WinHTTP. Requests use valid `pubStartDate`/`pubEndDate` filters and paginate at 2,000 records per page; the UI retains the newest 512 advisories as `NVD Intel`. These entries are not matched to CPE product/version ranges and cannot trigger Auto-Fix. This is recent-feed coverage, not a complete historical CVE database. CISA KEV/vendor feeds are not connected. The source supports an optional `NVD_API_KEY` environment variable.

A live run on the normal Windows host verified the app's WinHTTP fetch/parser against NVD: 2,825 records downloaded and parsed for the seven-day window; 512 retained for display. The feed can fail later due to network/API availability and preserves the last successful data on failure.

Optional periodic checks are saved per-user and run only while the GUI is open. They refresh the local registry/build-catalog inventory and can synchronize the seven-day NVD feed at the selected interval (15 minutes, 1 hour, 6 hours, or 24 hours). They do not run as a service or while the program is closed.

Auto-Fix can issue `winget upgrade --id` for a local application candidate only when it has a package ID. Success means the installer process exited successfully before timeout; it does not prove that a CVE is fixed. If the update fails and a verified executable path is available, Auto-Fix may add inbound and outbound Windows Firewall block rules as network containment. This can break that app's network functions and is disclosed in Ask Before Applying; Quiet Mode skips the confirmation. Partial rule creation is rolled back where possible. OS build matches are advisory only: installed KB state is not verified and no OS policy is changed automatically.

The registry watcher can trigger a local inventory/catalog re-scan after changes. It is not an external threat-intelligence feed.

## SmartSandbox

The GUI and CLI share the Sandboxie launcher. It accepts existing `.exe` files only, requires Sandboxie Plus and its WFP support to be installed, applies and verifies deny-all network settings and reduced admin rights before launch, and aborts if configuration or launch fails. The current machine has no Sandboxie installation, so only fail-closed behavior can be verified here; no app was launched.

## AI Team

Full Team sends one or five role-specific text prompts to the configured provider. Its manual local-review action collects current installed-app count, local catalog-candidate count, firewall status, and Sandboxie/WFP status. The team does not execute application exploits/fuzzing, inspect application source files, or apply fixes. Periodic role observations show process/listener/firewall telemetry only; they are not AI-driven tests. Provider/network/key failure must not be presented as a completed security test.

The NVIDIA-compatible provider uses `z-ai/glm-5.3-flash` through NVIDIA's OpenAI-compatible endpoint. Configure a valid replacement key in the app or `NVIDIA_API_KEY`; keys are protected with DPAPI when saved by the Windows app. The key pasted into the earlier conversation was exposed and should be revoked; it was not used for this verification.
