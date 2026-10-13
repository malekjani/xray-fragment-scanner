# v0.8.0 (2026-10-13)

- Shared FinalMask results tables for CLI and Web, top-three lowest measured response, exact masked links and detailed CSV export.
- V8 console wizard defaults to FinalMask-only while preserving other link settings; Combined Expert Mode remains available.
- No Progressive Scanning in V8 (reserved for V9).

# Changelog

All entries for unreleased drafts are **local-only** until an explicit publication decision is made. / تمام موارد زیر مربوط به پیش‌نویس خصوصی هستند.

## [0.8.0-draft.2] — 2026-10-13 (PRIVATE / UNRELEASED)

### Added / افزوده‌شده
- Independent `lib/compatibility/` package: version-aware FinalMask array gating, schema smoke harness with real `xray run -test` on a locked core, credential-redacted Requested/Generated/Observed preview and `EXPERIMENTAL` labeling.
- Full Expert matrix preservation with V8 core smoke compatibility reports; `diffs.jsonl` export.
- Web preview now displays compatibility status, selected core capability metadata, and effective differences without revealing URI secrets.
- Objective selector for Best Performance, Maximum Reliability, Balanced and Lowest Latency; actual download throughput is considered only when an observed valid throughput sample exists.
- Expanded internal bilingual glossary and offline regression coverage.

### Important boundaries / مرز قابلیت‌ها
- The compatibility registry documents known fragment schema changes but cannot automatically prove all future prerelease features. Unknown combinations require real `xray run -test` and operator field tests.
- Xray binary and real network are unavailable in the build environment, so the new core smoke harness is tested using a mocked executable.
- Progressive Scanning remains **V9**. Nothing has been published to GitHub.

## [0.8.0-draft.1] — 2026-10-13 (PRIVATE / UNRELEASED)

### Added / افزوده‌شده
- V8 Auto initial baseline-informed fixed matrix and Expert combination builder for address, ECH, fingerprint, and ordered Fragment/Header-Custom TCP FinalMask layers.
- Static compatibility checks, JSON round-trip verification, two-stage HTTPS scans, periodic baseline, repeatable random seed and optional capped throughput probes.
- Localhost-only web dashboard and local SQLite + CSV + JSONL + exact link exports; status-labeled Verified and Provisional link lists.
- Short bilingual root README, split `docs/README.fa.md` / `docs/README.en.md`, dedicated ranking and live benchmark docs, and five-line Debian Quickstart.
- Versioned **draft** release notes and provisional MIT `LICENSE` for owner approval before any public release.

### Known limitations / محدودیت‌های شناخته‌شده
- Real Debian ISP / real Xray runtime validation pending; Browser Dialer auto-testing unsupported.
- Interrupted-scan auto resume not completed. Progressive Scanning is deliberately deferred to V9.
- No GitHub Release, PR, tag, or public `main` update was made for V8.

## [0.7.x] — previous public development / توسعهٔ پیشین

Legacy Wizard, `optimize`, ECH/FinalMask scan modes, configurable official pre-release Xray selection and diagnostic helpers. See [archived extended README](docs/README-V7-REFERENCE.md) and git history for historical details; **no formal published V8 release is implied**.
