# About

**Threat Hunting Command Cheat Sheet** is a single-file reference for rapid triage, deep-dive hunting, and evidence collection on Windows, Linux, and macOS.

## What's inside

- **Per-OS hunting sections**: PowerShell deep dive (including the suspicious-switch table), Windows LOLBins, Linux processes/persistence/auditd, macOS launchd/unified logging
- **Native tool catalogs**: every native command-line tool per OS with its suspicious flags and parameters, attacker use, and MITRE ATT&CK mapping
- **Cross-platform section**: packet capture, DNS hunting, encoding/decoding, evidence collection, IOC patterns
- **Appendices**: top-10 triage commands per OS, a master suspicious-flags table, key event IDs and log sources, and a MITRE ATT&CK quick map

## Usage

Open `README.md` in the repository, or use it as a quick reference while hunting. All commands are defensive; use them only on systems you are authorized to investigate.

## License

[MIT](LICENSE)
