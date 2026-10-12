# Architecture

The project is split into small Bash modules.

## Entry point

```text
bin/xray-finalmask-scanner
```

Loads all modules and runs the main workflow.

## Modules

### `lib/env.sh`

Shared variables and mode helper functions.

### `lib/ui.sh`

Interactive prompts:

- scan mode selection
- instance count
- timeout
- local HTTP proxy port
- request count

### `lib/checks.sh`

Root check, dependency check, and log initialization.

### `lib/xray.sh`

Xray lifecycle:

- detect installed/latest Xray version
- install/update Xray
- stop active systemd service temporarily
- start Xray for each test
- restore original Xray service state

### `lib/config.sh`

Config logic:

- generate `config.json` from VLESS link
- inject finalmask or legacy fragment mode
- detect existing scan mode from config
- modify fragment parameters during scanning

### `lib/options.sh`

Scan option arrays:

- packets
- length
- legacy interval
- finalmask delay
- maxSplit

### `lib/scanner.sh`

Scan loop:

- unique random combination selection
- `curl` measurement
- result table
- top-three summary

## Current finalmask-header-custom + fragment chain

```json
{
  "finalmask": {
    "tcp": [
      {
        "type": "header-custom"
      },
      {
        "type": "fragment"
      }
    ]
  }
}
```

The first TCP mask is the fixed `header-custom` layer. The second TCP mask is the fragment layer that the scanner modifies.
