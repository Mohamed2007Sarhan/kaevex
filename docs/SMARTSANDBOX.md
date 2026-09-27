# SmartSandbox Windows backend

The GUI and CLI call the same `sbx_launch_sandboxie_exe` backend. The GUI's **Choose EXE Setup** button selects an existing application EXE or an EXE-format installer; **Run in Sandbox** sends that path to the backend. CLI: `sandbox-run <path-to-exe>`. The backend checks the file exists, discovers the separately installed Sandboxie-Plus `Start.exe` and `SbieIni.exe`, enables WFP, sets and verifies deny-all network policy and reduced admin rights, disables MSI installer exemptions, reloads configuration, and only then starts the EXE. Failure at any check aborts without a fallback launch. A per-path persistent box is used and a Desktop shortcut to relaunch the selected EXE is attempted.

MSI files are rejected. Sandboxie's MSI compatibility exemption weakens isolation, so this integration does not use it. An EXE installer may run in a box, but installers can fail when they expect elevated/system-wide installation. Its shortcut relaunches the selected installer; selecting the installed app's EXE is a separate operation. Installation success or full containment of installer side-effects is not asserted.

The SmartSandbox page now displays whether Sandboxie is installed and whether a session was started. The UI does not receive per-process network, filesystem, or API-call events from this backend. Those panels explicitly report that telemetry is unavailable instead of showing generated sample events. Process performance telemetry is unavailable for the external Sandboxie process as well.

This is Sandboxie's persistent process/file/registry virtualization, not a virtual-machine boundary. WFP rules block TCP/UDP traffic for the box; Windows' system resolver may still answer DNS queries. Use a disposable VM for high-risk malware analysis. Linux and macOS backends are outside this Windows-only integration.

Sandboxie-Plus is GPL-3.0 licensed and installs a signed kernel driver. This repository integrates with the installed product rather than bundling or silently installing its driver. Review the project's [license](https://github.com/sandboxie-plus/Sandboxie/blob/master/LICENSE) and release notes before redistributing it with Kaevex.
