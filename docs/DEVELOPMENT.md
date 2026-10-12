# Development

## Syntax check

Run:

```bash
bash -n bin/xray-finalmask-scanner
bash -n lib/*.sh
bash -n scripts/xray-fragment-scanner-single-file.sh
```

## Local test without touching system Xray

The current scanner is designed to manage `/usr/local/bin/xray` and the systemd `xray` service. Use a test VM or container if you do not want to touch your main system.

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
