# ExtSentry

https://extsentry.github.io

<img src="logo.png" alt="ExtSentry logo" width="240">

**Browser Extension Threat Intelligence**

ExtSentry transforms the community-curated [browser extension threat list](https://github.com/mthcht/awesome-lists) into ready-to-import feeds for 16+ security platforms. Point your SIEM, SOAR, or threat intel platform at the output and start detecting malicious, suspicious, and unwanted browser extensions.
Also include a remediation guide and forensic traces details for browser addons installations.

---

## Landing Page

`index.html` is a standalone React single-page app that serves as the project's documentation and feed download hub.


## Threat Intelligence Feeds

| Feed File | Platform / Format |
|---|---|
| `stix2_bundle.json` | STIX 2.1 Bundle - OpenCTI, TAXII, any CTI platform |
| `misp_event.json` | MISP Event (attributes + objects) |
| `misp_warninglist.json` | MISP Warning List |
| `sigma_rules_browser_extensions.yml` | Sigma Rules - process, file, registry + per-category |
| `yara_browser_extensions.yar` | YARA Rules - per-category + CRX hash matching |
| `suricata_browser_extensions.rules` | Suricata IDS Rules (HTTP URI matching) |
| `openioc_browser_extensions.ioc` | OpenIOC 1.1 (file path + registry) |
| `splunk_lookup_browser_extensions.csv` | Splunk Lookup Table |
| `elastic_detection_rule.ndjson` | Elastic Security Detection Rule (KQL) |
| `elastic_threat_intel.ndjson` | Elastic ECS-compliant Threat Intel docs |
| `sentinel_analytics_rule.kql` | Microsoft Sentinel KQL Analytics Rule |
| `sentinel_watchlist.csv` | Microsoft Sentinel Watchlist CSV |
| `opencti_import.csv` | OpenCTI CSV Connector import |
| `extsentry_ioc_feed.csv` | Enriched CSV (universal) |
| `extsentry_feed.json` | JSON Feed (universal) |
| `ioc_all_extension_ids.txt` | Plain text - all IDs, one per line |
| `ioc_malicious_extension_ids.txt` | Plain text - malicious only |
| `ioc_suspicious_extension_ids.txt` | Plain text - suspicious only |
| `ioc_crx_sha256_hashes.txt` | Plain text - CRX file SHA-256 hashes |

## Extension Checker & Analyzers
- The Extension Checker lets you look up extension IDs against the ExtSentry feeds. The Analyze Permissions tab accepts a manifest.json (or a .crx/.xpi upload) and produces a risk score with MITRE ATT&CK technique mapping for each permission.
- The Endpoint Inventory tab provides ready-to-run scripts (Python, PowerShell, Bash) that scan all user profiles on a system, enumerate every installed extension across Chrome, Edge, Brave, and Firefox, and cross-reference them against the live ExtSentry feed.

## Policy Generator
The Policy Generator creates browser extension blocklist/allowlist policies for Chrome (via ExtensionInstallBlocklist), Edge, and Firefox (ExtensionSettings). It can auto-populate the blocklist from the malicious feed and merge in custom IDs. The output is a ready-to-paste JSON policy or GPO-compatible configuration.

## Forensic Traces Guide
The Traces panel is a comprehensive forensic reference for investigating suspicious browser extensions across Windows, macOS, and Linux. It documents where browsers store extension data on disk (Preferences, Secure Preferences, extensions.json), relevant registry keys, process command-line patterns, and log sources to determine when and how an extension was installed and whether it was user-initiated or pushed via enterprise policy.

## Remediation Guide
The Remediation panel walks through step-by-step incident response for these malicious browser extensions

## Contributing
Found a malicious or suspicious extension that isn't in the feed? Contributions are welcome! The upstream data lives in the mthcht/awesome-lists repository.
To report an extension, open a pull request on the upstream CSV with the following fields: extension name, extension ID, wildcard pattern, category (malware, compromised, scam, PUP, PROXY/VPN, etc.), threat type (malicious, phishing, deceptive, offensive, greyware, sensitive, privacy, Defense Evasion), a reference link to a write-up or source, a description/comment, and the CRX SHA-256 hash if available. You can also use the "+ Contribute extension" button on the landing page, which pre-fills a GitHub issue template.
To improve the tooling (feed generator, landing page, detection rules, inventory scripts), open an issue or PR directly on this repository.

## Automated Updates

Feeds are rebuilt hourly via GitHub Actions. See `.github/workflows/generate_feeds.yml` for the workflow.

## Data Source

All extension data is sourced from [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists) - a community-maintained list of malicious, suspicious, and sensitive browser extensions. Contributions and corrections should be directed upstream.

## License

TLP:CLEAR — feed outputs are free to use, share, and integrate.
