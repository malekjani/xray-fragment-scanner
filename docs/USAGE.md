# Usage

## Start the scanner

```bash
sudo ./bin/xray-finalmask-scanner
```

The scanner performs these steps:

1. Checks dependencies.
2. Checks the installed Xray version.
3. Temporarily stops the active `xray` systemd service, if it is running.
4. Reads or generates `config.json`.
5. Lets you choose the scan mode.
6. Runs Xray with different fragment combinations.
7. Tests the local HTTP proxy using `curl`.
8. Prints the top three lowest average response times.
9. Restores the original Xray service state.

## Recommended inputs

For quick tests:

```text
Instances: 10
Timeout: 10
HTTP port: 10809
Requests per instance: 3
```

For more reliable results:

```text
Instances: 30
Timeout: 10
HTTP port: 10809
Requests per instance: 5
```

## Output files

```text
logs/pings.txt
logs/xraylogs.txt
logs/xraylogs.error.txt
```

## Important note about header-custom

In this version, `finalmask-header-custom + fragment` uses a fixed `header-custom` packet. The scanner still changes only fragment parameters. Header profile scanning is planned for a later version.
