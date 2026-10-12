# Guided scanner — VLESS / VMess / Trojan

Start in the project root:

```bash
./bin/xray-finalmask-scanner
```

The scanner prompts for a VLESS, VMess AEAD, VMess Base64 JSON or Trojan
share link. In a terminal, the paste is hidden to avoid displaying your
credentials. **Do not pass passwords or share links directly as command-line
arguments**. For a private non-interactive scan use `--link-file` with file
permission `0600`.

Next prompts, in order:

1. Validate and summarize the link without printing credentials.
2. Choose Fragment, FinalMask, or both (baseline always included).
3. Keep the original address or add custom IPs/hosts.
4. Choose example parameter grids or define semicolon-delimited lists of
   packets, lengths arrays, delays arrays and maxSplit; optionally add a
   second fragment layer or custom mask JSON file.
5. Select HTTPS attempts per candidate, timeout, maximum candidates, and
   whether to run dry-run (no network needed).
6. Review and confirm.

For example, enter `0,104,1;6,98,1` for two **different** `lengths`
variants, not one combined array. A length array is comma-separated; the
variants are semicolon-separated.

Output directory (private, mode 0700):

- `results.csv`: every candidate's precise fragment/finalmask fields,
  protocol, success ratio, response time, P95, and unique ID.
- `ranked.csv`: sorted by success ratio, P95 and average HTTPS latency.
- `links.csv` / `links.txt`: full share URI for every corresponding ID.
- `manifest.jsonl`: per-ID exact mask JSON, delays and per-request timings.
- `best-link.txt` and `best-config.json`: only when a real all-success winner
  exists. `best-vless.txt` is also generated for VLESS compatibility.

Generated files containing credentials have file permission 0600. Never
commit them to a public repository. Dry-run results are not treated as
measured success.

## Compatibility and safeguards

- VLESS links retain `encryption` (including ML-KEM values), TLS/ECH, REALITY
  and WS/HTTPUpgrade/XHTTP fields recognized by the share parser.
- VMess AEAD links use Xray's current flat outbound `security` field.
- VMess legacy Base64 JSON inputs (`aid=0`) are converted to VMess AEAD
  **for the modified share links**, because QR v2 JSON does not standardize
  FinalMask. Not all older apps can import AEAD+fm; verify on your client.
- Trojan requires TLS and preserves the percent-encoded password.
- Unknown query parameters and unsupported legacy transport settings are
  rejected rather than silently dropped.
- For VLESS/VMess/Trojan, all variants are parsed back and compared to the
  tested Xray outbound settings before the scan.
- `--legacy-menu` opens the original root-requiring Bash scanner menu.

Docs: https://github.com/XTLS/Xray-core/discussions/716,
https://xtls.github.io/en/config/outbounds/vmess.html,
https://xtls.github.io/en/config/outbounds/trojan.html
