# Development

## Syntax check

Run:

```bash
bash -n bin/xray-finalmask-scanner
bash -n lib/*.sh
bash -n scripts/xray-fragment-scanner-single-file.sh
```

## Local test without touching system Xray

Use `--method optimize --dry-run` or `--method irancell --dry-run` for safe offline tests. Modern Python modes never install Xray, change systemd or require root. The **historical** Bash `--legacy-menu` mode can install/update `/usr/local/bin/xray` and temporarily stop the system Xray service; test that path on a disposable VM only.

## Adding a new mode

1. Add the mode name in `lib/ui.sh`.
2. Add mode helper logic in `lib/env.sh`, if needed.
3. Add config injection in `lib/config.sh`.
4. Add scanner behavior in `lib/scanner.sh`, if the mode changes how combinations are generated.
5. Update `README.md` and `docs/ROADMAP.md`.

## Adding header profile scanning later

Suggested path:

1. Move fixed header profiles into `profiles/header-profiles.json`.
2. Add a function like `modify_config_finalmask_header` in `lib/config.sh`.
3. Add `HeaderProfile` to the result tuple.
4. Print `HeaderProfile` in the result table.
5. Keep fixed header mode as the default, and add profile scanning as a separate mode.

## Python modules and regression tests

- `lib/network_scan.py` — IP/ECH and IP/FinalMask matrix; preserve-by-default TLS/ECH; private linked exports.
- `lib/optimize.py` — randomized/balanced parameter combinations, HTTPS timing and ranking, per-ID link exports.
- `lib/share_codec.py` — share parsing/round-trip for VLESS, VMess AEAD/legacy and Trojan.
- `lib/wizard.py` — six-step interactive workflow, no credentials in CLI arguments.
- `tests/test_network_scan.py`, `tests/test_live_exports.py`, `tests/test_legacy_ech.py`, `tests/test_optimize.py`, `tests/test_share_wizard.py` — unit, regression and dry-run checks.

```sh
python3 -m unittest discover -s tests -v
python3 -m py_compile lib/*.py
bash -n bin/xray-finalmask-scanner lib/*.sh
```

Use non-sensitive mock URIs in test fixtures. Never commit real user links or scan exports.
